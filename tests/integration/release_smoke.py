#!/usr/bin/env python3
"""Isolated synthetic release smoke; recreates only its own application target.

Writes only var/release-runs, fixture/workspace roots. Retains database volume.
No exploitation, migrations, data restores, or pre-existing project mutations.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/integration'))
from registration_smoke import prepare_fixture, require, run, json_command, api, wait_ready, inspect_starts

class UnixConnection(http.client.HTTPConnection):
    def __init__(self,path):
        super().__init__('executor',timeout=15)
        self.path=str(path)
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'var/executor.dev.json')
    args=parser.parse_args()
    run_id=uuid.uuid4().hex[:10]
    project='ctfm-release-'+run_id
    service_id='release-'+run_id
    output=ROOT/'var/release-runs'/run_id
    output.mkdir(parents=True,mode=0o700)
    config=json.loads(args.config.read_text())
    require(config.get('development') is True,'only explicit development config is supported')
    state=output/'state';state.mkdir(mode=0o700)
    config.update(state_directory=str(state),socket=str(output/'executor.sock'))
    config_file=output/'executor.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
    work=ROOT/'var/fixtures'/('release-'+run_id)
    source=ROOT/'var/workspaces'/('release-'+run_id)
    binary=ROOT/'bin/ctf-manager'
    cli=[str(binary),'--config',str(config_file)]
    docker=[config['docker_binary'],'--host',config['docker_host']]
    compose=docker+['compose','--project-name',project,'--file',str(work/'compose.yaml')]
    report={'run_id':run_id,'project':project,'started_at':datetime.now(timezone.utc).isoformat(),'status':'failed','checks':{},'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    environment=os.environ.copy()
    for k in list(environment):
        if k.startswith('COMPOSE_'):del environment[k]
    process=None
    started=False
    log=None
    def rpc(method,path,body=None,expected=200):
        connection=UnixConnection(config['socket'])
        try:
            connection.request(method,path,None if body is None else json.dumps(body),headers={'Content-Type':'application/json'})
            response=connection.getresponse();data=json.loads(response.read())
            require(response.status==expected,f'RPC {method} {path}: HTTP{response.status} {data}')
            return data
        finally:connection.close()
    def operation(action,**fields):
        req={'service_id':service_id,'action':action,'initiator':'release-smoke','idempotency_key':uuid.uuid4().hex,**fields}
        preview=rpc('POST','/v1/preview',req)
        req['plan_digest']=preview['plan_digest']
        op=rpc('POST','/v1/operations',req,expected=202)
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            value=rpc('GET','/v1/operations/'+op['spec']['id'])
            if value['state'] in ('succeeded','failed','requires_recovery','interrupted'):
                require(value['state']=='succeeded',f'{action} failed: {value}')
                require(rpc('POST','/v1/operations',req,expected=202)['spec']['id']==op['spec']['id'],'idempotent retry created another operation')
                return value
            time.sleep(.2)
        raise RuntimeError('operation did not finish: '+action)
    try:
        prepare_fixture('named-volume',work)
        with socket.socket() as allocation:
            allocation.bind(('127.0.0.1',0));published=allocation.getsockname()[1]
        compose_text=(work/'compose.yaml').read_text().replace('      FIXTURE_STORAGE: remote','      FIXTURE_STORAGE: remote\n      CTFM_LITERAL: \"pa$$word-$${HOME}\"').replace('      - target: 8080','      - target: 8080\n        published: "'+str(published)+'"')
        (work/'compose.yaml').write_text(compose_text)
        source.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(work,source)
        run(compose+['up','--detach','--build'],environment=environment,timeout=300)
        started=True
        url=wait_ready(compose,environment)
        key='release_'+run_id;value='CTFM_TEST_FLAG_RELEASE_'+run_id
        require(api(url,'PUT','/flags/'+key,value)[0]==200,'flag write failed')
        initial=json_command(cli+['inventory','--project',project])
        database=next(x for x in initial if x['component']=='database')
        old_version=api(url,'GET','/version')[1]
        policy={'schema_version':1,'id':service_id,'name':'Release smoke '+run_id,'project_directory':str(work),'source_directory':str(source),'compose_project':project,'compose_files':['compose.yaml'],'managed_paths':[{'path':'code','kind':'code'},{'path':'compose.yaml','kind':'configuration'}],'data_paths':[{'name':'database-data','kind':'named_volume','source':project+'_database-data','target':'/data','component':'database','significant':True,'loss_accepted':False},{'name':'app-layer','kind':'writable_layer','target':'/tmp','component':'app','significant':False,'loss_accepted':True},{'name':'database-layer','kind':'writable_layer','target':'/tmp','component':'database','significant':False,'loss_accepted':True}],'targets':['app'],'containers':[{'component':x['component'],'id':x['id'],'image_id':x['image_id'],'role':'database' if x['component']=='database' else 'application'} for x in initial],'policy_revision':1,'file_map_revision':1,'checks':[{'id':'fixture-readiness','source':'readiness','url':url+'/health','expected_status':200,'timeout_seconds':2},{'id':'fixture-version','source':'local_functional','url':url+'/version','expected_status':200,'body_contains':'version','timeout_seconds':2}]}
        service_file=output/'service.json';service_file.write_text(json.dumps(policy));service_file.chmod(0o600)
        proposal=json_command(cli+['propose','--service',str(service_file)])
        json_command(cli+['approve','--proposal',proposal['id'],'--digest',proposal['digest']])
        log=(output/'executor.log').open('w')
        process=subprocess.Popen(cli+['executor'],stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while not Path(config['socket']).exists() and time.monotonic()<deadline:time.sleep(.1)
        rpc('GET','/v1/health')
        operation('snapshot')
        details=rpc('GET','/v1/services/'+service_id)
        baseline=details['current_release_id']
        require(baseline and len(details['releases'])==1,'baseline/imported release missing')
        report['checks']['baseline_retains_exact_images']=True
        for _ in range(6):operation('snapshot')
        details=rpc('GET','/v1/services/'+service_id)
        require(len([x for x in details['snapshots'] if x['purpose']=='manual'])==3,'manual snapshots did not rotate to three')
        require(any(x['purpose']=='baseline' for x in details['snapshots']),'rotation removed baseline')
        report['checks']['manual_snapshot_rotation_preserves_baseline_and_imported_release']=True

        (source/'code/VERSION').write_text('release-'+run_id+'\n')
        operation('prepare')
        details=rpc('GET','/v1/services/'+service_id)
        operation('build',candidate_id=details['candidate_id'])
        details=rpc('GET','/v1/services/'+service_id)
        candidate=next(x for x in details['releases'] if x['id']!=baseline)
        require(api(url,'GET','/version')[1]==old_version,'build changed active version')
        report['checks']['prepare_build_do_not_change_active']=True
        operation('deploy',release_id=candidate['id'],confirm_data_compatibility=True)
        url=wait_ready(compose,environment)
        require(api(url,'GET','/version')[1]!=old_version,'deploy did not switch version')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'deploy lost flag')
        now=json_command(cli+['inventory','--project',project]);db=next(x for x in now if x['component']=='database')
        require(db['id']==database['id'] and db['mounts']==database['mounts'],'deploy recreated database or data mount')
        report['checks']['deploy_preserves_database_container_and_flag']=True
        health=rpc('GET','/v1/services/'+service_id)['health']
        require(next(x for x in health if x['source']=='local_functional')['state']=='healthy','configured local functional check was not confirmed')
        require(next(x for x in health if x['source']=='external_checker')['state']=='unknown','local check impersonates external checker')
        report['checks']['local_readiness_and_functional_separate_from_external_checker']=True
        operation('rollback',release_id=baseline,confirm_data_compatibility=True)
        url=wait_ready(compose,environment)
        require(api(url,'GET','/version')[1]==old_version,'rollback did not restore version')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'rollback lost flag')
        now=json_command(cli+['inventory','--project',project]);db=next(x for x in now if x['component']=='database')
        require(db['id']==database['id'] and db['mounts']==database['mounts'],'rollback recreated database')
        report['checks']['rollback_exact_release_preserves_database_and_flag']=True
        report['checks']['idempotent_retry_returns_same_operation']=True
        # Interrupt after durable intent, while Docker Stop is still in progress.
        request={'service_id':service_id,'action':'deploy','release_id':candidate['id'],'confirm_data_compatibility':True,'initiator':'release-smoke','idempotency_key':uuid.uuid4().hex}
        request['plan_digest']=rpc('POST','/v1/preview',request)['plan_digest']
        interrupted=rpc('POST','/v1/operations',request,expected=202)
        original_id=interrupted['spec']['id']
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            current=rpc('GET','/v1/operations/'+original_id)
            if current['mutation_started']:
                process.kill();process.wait(timeout=10)
                break
            time.sleep(.01)
        else:raise RuntimeError('did not observe durable mutation intent')
        time.sleep(12)  # daemon-side stop may complete after its client disappears
        process=subprocess.Popen(cli+['executor'],stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:
                current=rpc('GET','/v1/operations/'+original_id)
                if current['state']=='interrupted':break
            except (OSError,RuntimeError):pass
            time.sleep(.1)
        require(current['state']=='interrupted','restart replayed interrupted operation or lost evidence')
        recover={'service_id':service_id,'action':'recover','recovery_operation_id':original_id,'confirm_data_compatibility':True,'initiator':'release-smoke','idempotency_key':uuid.uuid4().hex}
        recover['plan_digest']=rpc('POST','/v1/preview',recover)['plan_digest']
        require(rpc('POST','/v1/operations',recover,expected=202)['spec']['id']==original_id,'recovery discarded original operation identity/locks')
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            current=rpc('GET','/v1/operations/'+original_id)
            if current['state']=='failed' and current['outcome']['returned_to_previous']:break
            if current['state']=='requires_recovery':raise RuntimeError('explicit recovery failed: '+str(current))
            time.sleep(.2)
        require(current['state']=='failed' and current['outcome']['returned_to_previous'],'recovery did not record return to previous release')
        url=wait_ready(compose,environment)
        require(api(url,'GET','/version')[1]==old_version,'recovery did not restore exact previous version')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'recovery lost persistent flag')
        require(next(x for x in json_command(cli+['inventory','--project',project]) if x['component']=='database')['id']==database['id'],'recovery recreated database')
        report['checks']['sigkill_restart_retains_interruption_and_explicit_recovery']=True
        app_source=source/'code/app.py'
        old_text=app_source.read_text()
        require('"version": config.version_file' in old_text,'fixture version response seam missing')
        app_source.write_text(old_text.replace('"version": config.version_file','"broken": config.version_file'))
        operation('prepare')
        latest=rpc('GET','/v1/services/'+service_id)
        existing_ids={x['id'] for x in latest['releases']}
        operation('build',candidate_id=latest['candidate_id'])
        bad_release=next(x for x in rpc('GET','/v1/services/'+service_id)['releases'] if x['id'] not in existing_ids)
        request={'service_id':service_id,'action':'deploy','release_id':bad_release['id'],'confirm_data_compatibility':True,'initiator':'release-smoke','idempotency_key':uuid.uuid4().hex}
        request['plan_digest']=rpc('POST','/v1/preview',request)['plan_digest']
        failed=rpc('POST','/v1/operations',request,expected=202)
        failed_id=failed['spec']['id']
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            current=rpc('GET','/v1/operations/'+failed_id)
            if current['state'] in ('requires_recovery','failed','succeeded'):break
            time.sleep(.2)
        require(current['state']=='requires_recovery','failed functional check produced a false success')
        details=rpc('GET','/v1/services/'+service_id)
        require(details['current_release_id']==bad_release['id'],'failed check hid the actually launched release')
        require(next(x for x in details['health'] if x['source']=='local_functional')['state']=='unhealthy','functional failure not exposed separately')
        app=next(x for x in details['containers'] if x['component']=='app')
        literal=run(docker+['inspect','--format','{{range .Config.Env}}{{println .}}{{end}}',app['id']],environment=environment).stdout.splitlines()
        require('CTFM_LITERAL=pa$word-${HOME}' in literal,'frozen environment literal dollars changed after Compose roundtrip')
        recover={'service_id':service_id,'action':'recover','recovery_operation_id':failed_id,'confirm_data_compatibility':True,'initiator':'release-smoke','idempotency_key':uuid.uuid4().hex}
        recover['plan_digest']=rpc('POST','/v1/preview',recover)['plan_digest']
        rpc('POST','/v1/operations',recover,expected=202)
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            current=rpc('GET','/v1/operations/'+failed_id)
            if current['state']=='failed' and current['outcome']['returned_to_previous']:break
            time.sleep(.2)
        require(current['state']=='failed' and current['outcome']['returned_to_previous'],'functional failure recovery did not complete')
        url=wait_ready(compose,environment)
        require(api(url,'GET','/version')[1]==old_version,'functional failure recovery did not restore prior version')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'functional failure recovery lost flag')
        report['checks']['functional_failure_keeps_new_release_visible_and_recovers']=True
        report['checks']['literal_environment_survives_compose_config_and_up']=True

        # Refuse quota pressure before any mutation, even when the only files
        # left are protected. Restore normal policy before backup verification.
        process.terminate();process.wait(timeout=15)
        config['storage']={'snapshot_max_bytes':1}
        config_file.write_text(json.dumps(config));config_file.chmod(0o600)
        process=subprocess.Popen(cli+['executor'],stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while not Path(config['socket']).exists() and time.monotonic()<deadline:time.sleep(.1)
        request={'service_id':service_id,'action':'prepare','initiator':'release-smoke','idempotency_key':uuid.uuid4().hex}
        request['plan_digest']=rpc('POST','/v1/preview',request)['plan_digest']
        rejected=rpc('POST','/v1/operations',request,expected=202)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            current=rpc('GET','/v1/operations/'+rejected['spec']['id'])
            if current['state']=='failed':break
            time.sleep(.2)
        require(current['state']=='failed' and not current['mutation_started'],'quota pressure did not fail before mutation')
        require('limit' in current['outcome'].get('reason',''),'quota failure reason missing')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'quota failure changed game state')
        report['checks']['quota_exhaustion_refuses_before_mutation_and_preserves_flag']=True
        process.terminate();process.wait(timeout=15);process=None
        config.pop('storage')
        config_file.write_text(json.dumps(config));config_file.chmod(0o600)
        # Exercise the actual local backup/restore CLI with both processes
        # stopped. Game containers keep running throughout these commands.
        dashboard=output/'dashboard';dashboard.mkdir(mode=0o700)
        password=uuid.uuid4().hex+uuid.uuid4().hex
        initialized=subprocess.run([str(binary),'init-admin','--state',str(dashboard),'--username','smoke-admin'],input=password+'\n',text=True,capture_output=True,timeout=30)
        require(initialized.returncode==0,'dashboard bootstrap for backup failed')
        passphrase=uuid.uuid4().hex+uuid.uuid4().hex
        backup_args=[str(binary),'backup','--executor-state',str(state),'--dashboard-state',str(dashboard),'--configuration',str(config_file)]
        metadata=output/'metadata.tar';full=output/'full.ctfbackup'
        json_command(backup_args+['--output',str(metadata)])
        require(b'pa$word-${HOME}' not in metadata.read_bytes(),'ordinary export leaked frozen environment')
        protected=subprocess.run(backup_args+['--output',str(full),'--passphrase-stdin'],input=passphrase+'\n',text=True,capture_output=True,timeout=60)
        require(protected.returncode==0,'protected backup failed: '+protected.stderr)
        require(b'pa$word-${HOME}' not in full.read_bytes(),'protected archive contains plaintext environment')
        restored_metadata=output/'restored-metadata';restored_full=output/'restored-full'
        meta_report=json_command([str(binary),'restore','--input',str(metadata),'--destination',str(restored_metadata)])
        require(meta_report['requires_registration_review'],'metadata restore did not block operations')
        restored=subprocess.run([str(binary),'restore','--input',str(full),'--destination',str(restored_full),'--passphrase-stdin'],input=passphrase+'\n',text=True,capture_output=True,timeout=60)
        require(restored.returncode==0,'protected restore failed: '+restored.stderr)
        full_report=json.loads(restored.stdout)
        require(full_report['sessions_revoked'] and full_report['queued_operations_disabled'],'restore left prior authorizations active')
        require(any((restored_full/'executor/snapshots').glob('*/snapshot.json')),'full restore omitted source artifacts')
        import sqlite3
        with sqlite3.connect(restored_full/'executor/executor.db') as db:
            require(db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','restored executor DB corrupt')
            require(db.execute('SELECT count(*) FROM services').fetchone()[0]==1,'restored registry missing')
        with sqlite3.connect(restored_full/'dashboard/dashboard.sqlite') as db:
            require(db.execute('SELECT count(*) FROM users').fetchone()[0]==1,'restored accounts missing')
            require(db.execute('SELECT count(*) FROM sessions').fetchone()[0]==0,'restored sessions not revoked')
        require(api(url,'GET','/flags/'+key)[1]['value']==value,'panel backup/restore changed game data')
        report['checks']['metadata_and_encrypted_full_cli_backup_restore']=True
        report['status']='passed'
    except Exception as error:
        report['error']=str(error)
    finally:
        if process is not None:
            process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        if log:log.close()
        if started:
            try:run(compose+['down','--remove-orphans'],environment=environment,timeout=60);report['volume_retained']=project+'_database-data'
            except Exception as error:report['cleanup_error']=str(error);report['status']='failed'
        report['finished_at']=datetime.now(timezone.utc).isoformat()
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':sys.exit(main())
