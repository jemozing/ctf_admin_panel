#!/usr/bin/env node
'use strict';

// Real built React UI with a loopback-only synthetic API. This is a registration
// UI regression, not Docker, executor or data-loss acceptance.
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {once} = require('node:events');
const result = {passed: false, checks: [], scope: {real_built_ui: true, synthetic_api: true, loopback_only: true, executor: false, docker: false, vm: false, screenshots: false, traces: false}};
let server, browser, context;
function check(name, value) { result.checks.push({name, passed: Boolean(value)}); if (!value) throw new Error(name); }

async function main() {
  const dist = fs.realpathSync(process.argv[2] || path.join(__dirname, '../../web/dist'));
  if (!fs.statSync(path.join(dist, 'index.html')).isFile()) throw new Error('built_frontend_required');
  let playwright;
  try { playwright = require('playwright'); }
  catch { playwright = require(path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')); }
  if (!fs.existsSync(playwright.chromium.executablePath())) throw new Error('cached_chromium_unavailable_no_install_attempted');
  const root = '/srv/games/filestorage';
  const csrf = 'fixture-only-csrf';
  const digest = 'sha256:' + 'a'.repeat(64);
  const at = '2026-11-03T00:00:00Z';
  const proposals = [], resolutions = [];
  let inspectCount = 0, denyNext = false, unexpected = 0;
  const runtimeErrors = [];
  function draft() {
    inspectCount++;
    return {schema_version: 1, id: 'draft-fixture-' + inspectCount, name: 'Filestorage fixture', compose_project: 'filestorage-fixture', project_directory: root, source_directory: '/srv/workspaces/draft-fixture-' + inspectCount, compose_files: ['docker-compose.yml'], targets: ['cleaner', 'web'], managed_paths: [], policy_revision: 1, file_map_revision: 1,
      containers: ['cleaner', 'web'].map((component, index) => ({component, role: 'application', id: String(index + 1).repeat(64), image_id: digest})),
      data_paths: ['cleaner', 'web'].flatMap(component => [{name: 'layer-' + component, kind: 'writable_layer', target: '/ctfm-writable-layer', component, significant: false, loss_accepted: false}, {name: 'bind-' + component, kind: 'bind', source: root, target: '/app', component, significant: true, loss_accepted: false}]),
    };
  }
  function json(response, status, value) { response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}); response.end(JSON.stringify(value)); }
  async function body(request) {
    let value = '';
    for await (const chunk of request) { value += chunk; if (value.length > 65536) throw new Error('fixture_request_limit'); }
    return JSON.parse(value);
  }
  async function handle(request, response) {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (request.method === 'GET' && url.pathname === '/api/auth/session') return json(response, 200, {user: {id: 'fixture-admin', username: 'fixture-admin', role: 'admin', disabled: false, sensitive_access: true, created_at: at}, csrf_token: csrf, expires_at: '2099-01-01T00:00:00Z'});
    if (request.method === 'GET' && ['/api/services', '/api/operations'].includes(url.pathname)) return json(response, 200, []);
    if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, {executor: 'ok'});
    if (request.method === 'GET' && url.pathname === '/api/registration/options') return json(response, 200, {discovery_roots: ['/srv/games'], workspace_roots: ['/srv/workspaces']});
    if (request.method === 'POST' && url.pathname.startsWith('/api/registration/')) {
      const input = await body(request);
      if (request.headers['x-csrf-token'] !== csrf) throw new Error('fixture_missing_csrf');
      if (url.pathname === '/api/registration/inspect') {
        if (input.project_directory !== root) throw new Error('fixture_wrong_project_path');
        return json(response, 200, {service: draft(), warnings: ['No safe managed code paths were inferred. Add explicit code/configuration paths excluding game data.']});
      }
      if (url.pathname === '/api/registration/managed-paths') {
        resolutions.push(input);
        await new Promise(resolve => setTimeout(resolve, 100));
        if (denyNext) { denyNext = false; return json(response, 403, {code: 'fixture_resolution_denied', message: 'Fixture: code binding resolution denied'}); }
        const names = [...input.code_bindings].sort();
        const managed = names.join(',') === 'bind-cleaner,bind-web' ? [{path: 'Dockerfile', kind: 'configuration'}, {path: 'main.py', kind: 'code'}, {path: 'templates', kind: 'code', exclusions: ['.env']}] : [];
        return json(response, 200, {managed_paths: managed});
      }
      if (url.pathname === '/api/registration/proposals') {
        proposals.push(input);
        return json(response, 200, {id: 'proposal-fixture', digest, configuration_digest: digest, service: input.service, actor: 'fixture-admin', created_at: at});
      }
    }
    if (url.pathname.startsWith('/api/')) { unexpected++; return json(response, 404, {code: 'unexpected_fixture_request', message: 'Unexpected fixture endpoint'}); }
    const name = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
    const file = path.resolve(dist, name);
    if (request.method !== 'GET' || !file.startsWith(dist + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile() || fs.realpathSync(file) !== file) { response.writeHead(404).end(); return; }
    const types = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css'};
    response.writeHead(200, {'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store'});
    fs.createReadStream(file).pipe(response);
  }
  server = http.createServer((request, response) => { handle(request, response).catch(() => { if (!response.headersSent) json(response, 500, {code: 'fixture_error', message: 'Fixture request failed'}); else response.destroy(); }); });
  server.on('upgrade', (request, socket) => { if (request.url !== '/api/stream') unexpected++; socket.end('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'http://127.0.0.1:' + server.address().port;
  browser = await playwright.chromium.launch({headless: true});
  result.browser_version = browser.version();
  context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block'});
  await context.route('**/*', route => { if (new URL(route.request().url()).origin === origin) return route.continue(); unexpected++; return route.abort(); });
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  page.on('pageerror', error => runtimeErrors.push(error.name));
  await page.goto(origin, {waitUntil: 'domcontentloaded'});
  await page.getByRole('button', {name: 'Добавить сервис', exact: true}).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Путь к сервису', {exact: true}).fill(root);
  await dialog.getByRole('button', {name: 'Найти сервис', exact: true}).click();
  const proposalButton = () => dialog.getByRole('button', {name: 'Проверить регистрацию', exact: true});
  const managed = () => dialog.locator('.managed-paths .managed-path');
  const consent = () => dialog.getByRole('checkbox', {name: 'Разрешаю обновление кода и возможную потерю данных внутри управляемых путей перечисленных bind-каталогов.', exact: true});
  await dialog.getByLabel('Назначение bind-web', {exact: true}).waitFor();
  check('root_bind_mode_starts_off_and_empty_paths_block_proposal', await managed().count() === 0 && await proposalButton().isDisabled() && await dialog.getByLabel('Назначение bind-web', {exact: true}).inputValue() === 'significant' && await consent().count() === 0);
  async function classify(name, value, expected = 200) {
    const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/registration/managed-paths');
    await dialog.getByLabel('Назначение ' + name, {exact: true}).selectOption(value);
    check('pending_resolution_disables_proposal_' + resolutions.length, await proposalButton().isDisabled());
    const reply = await response;
    await dialog.getByRole('status').waitFor({state: 'hidden'});
    check('resolution_status_' + resolutions.length, reply.status() === expected);
  }
  await classify('bind-web', 'code');
  check('one_shared_bind_opt_in_keeps_other_data_bind_protected', await managed().count() === 0 && await dialog.getByLabel('Назначение bind-cleaner', {exact: true}).inputValue() === 'significant');
  await classify('bind-cleaner', 'code');
  check('both_bind_opt_ins_show_server_managed_paths_and_notice', await managed().count() === 3 && await dialog.getByText('Назначение bind-каталогов изменено. Управляемые пути пересчитаны; проверьте список и исключения перед подтверждением.', {exact: true}).isVisible() && await proposalButton().isDisabled() && !(await consent().isChecked()));
  for (const component of ['cleaner', 'web']) await dialog.getByLabel('Назначение layer-' + component, {exact: true}).selectOption('disposable');
  await consent().check();
  check('separate_explicit_data_loss_consent_enables_proposal', await proposalButton().isEnabled() && proposals.length === 0);
  await dialog.getByLabel('Обновлять cleaner', {exact: true}).uncheck();
  check('code_consumer_must_be_an_update_target_and_scope_edit_resets_consent', await proposalButton().isDisabled() && !(await consent().isChecked()) && await dialog.getByText('Отметьте «Обновлять» у каждого компонента с кодовым bind-каталогом, чтобы он останавливался при замене файлов.', {exact: true}).isVisible());
  await dialog.getByLabel('Обновлять cleaner', {exact: true}).check();
  await consent().check();
  denyNext = true;
  await classify('bind-web', 'significant', 403);
  check('failed_resolution_retains_previous_safe_paths_and_classification', await managed().count() === 3 && await dialog.getByLabel('Назначение bind-web', {exact: true}).inputValue() === 'code' && await dialog.getByRole('alert').getByText('Fixture: code binding resolution denied', {exact: true}).isVisible() && !(await consent().isChecked()) && await proposalButton().isDisabled());
  await classify('bind-web', 'significant');
  check('leaving_code_mode_recalculates_and_removes_managed_scope', await managed().count() === 0 && await dialog.getByLabel('Назначение bind-web', {exact: true}).inputValue() === 'significant' && await proposalButton().isDisabled());
  await classify('bind-web', 'code');
  await consent().check();
  await proposalButton().click();
  await dialog.getByRole('button', {name: 'Зарегистрировать', exact: true}).waitFor();
  const selected = proposals[0]?.service?.data_paths?.filter(data => data.kind === 'bind');
  check('proposal_carries_exact_code_bind_loss_flags_and_selected_targets', proposals.length === 1 && selected.length === 2 && selected.every(data => data.allow_code_updates === true && data.loss_accepted === true && data.significant === false && data.source === root && data.target === '/app') && ['web', 'cleaner'].every(component => proposals[0].service.targets.includes(component)));
  check('final_confirmation_names_risk_and_requires_new_approval_checkbox', await dialog.getByText('Подтверждается обновление кода с возможной потерей данных в управляемых путях этих bind-каталогов:', {exact: false}).isVisible() && await dialog.getByRole('button', {name: 'Зарегистрировать', exact: true}).isDisabled());
  await dialog.getByRole('button', {name: 'Изменить настройки', exact: true}).click();
  await dialog.getByRole('button', {name: 'Назад', exact: true}).click();
  await dialog.getByRole('button', {name: 'Найти сервис', exact: true}).click();
  await dialog.getByLabel('Назначение bind-web', {exact: true}).waitFor();
  check('new_draft_resets_mode_consent_and_managed_paths', inspectCount === 2 && await managed().count() === 0 && await consent().count() === 0 && await dialog.getByLabel('Назначение bind-web', {exact: true}).inputValue() === 'significant');
  check('no_runtime_errors_or_external_requests_or_approval_side_effects', runtimeErrors.length === 0 && unexpected === 0 && proposals.length === 1 && resolutions.every(value => value.service_id === 'draft-fixture-1' && Object.keys(value).sort().join(',') === 'code_bindings,service_id'));
  result.resolution_requests = resolutions.length;
  result.mock_proposals = proposals.length;
  result.passed = true;
}
main().catch(error => { result.error = {name: error.name, message: error.message}; process.exitCode = 1; }).finally(async () => {
  if (context) await context.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  console.log(JSON.stringify(result, null, 2));
});
