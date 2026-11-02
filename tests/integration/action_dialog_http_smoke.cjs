#!/usr/bin/env node
'use strict';

// Real built dashboard UI, synthetic HTTP API only. No executor, Docker or VM.
// The browser reaches an insecure .test origin mapped to a loopback-only server;
// ordinary localhost would hide the crypto.randomUUID regression.
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {once} = require('node:events');

const result = {passed: false, checks: [], preview_requests: 0, mock_operation_submissions: 0, scope: {
  real_built_ui: true, synthetic_api: true, insecure_http_origin: true,
  temporary_browser_profile: true, loopback_server_only: true,
  real_backend: false, docker_used: false, vm_used: false,
  screenshots: false, traces: false,
}};
let server;
let browser;
let context;

function check(name, value) {
  result.checks.push({name, passed: Boolean(value)});
  if (!value) throw new Error(name);
}

async function main() {
  const dist = fs.realpathSync(process.argv[2] || path.join(__dirname, '../../web/dist'));
  if (!fs.statSync(path.join(dist, 'index.html')).isFile()) throw new Error('built_frontend_required');
  let playwright;
  try {
    playwright = require('playwright');
  } catch {
    const cached = path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
    if (!fs.existsSync(cached)) throw new Error('cached_playwright_unavailable_no_install_attempted');
    playwright = require(cached);
  }
  if (!fs.existsSync(playwright.chromium.executablePath())) throw new Error('cached_chromium_unavailable_no_install_attempted');

  const at = '2026-11-02T00:00:00Z';
  const digest = 'sha256:' + 'a'.repeat(64);
  const service = {
    id: 'dialog-fixture', name: 'HTTP dialog fixture', compose_project: 'dialog-fixture',
    project_directory: '/srv/fixture/service', source_directory: '/srv/fixture/workspace',
    targets: ['app'], policy_revision: 1, managed_paths: [{path: 'app', kind: 'code'}],
    data_paths: [], containers: [{component: 'app', role: 'application'}],
  };
  const releases = ['release-first', 'release-second'].map((id, index) => ({
    id, service_id: service.id, created_at: index ? '2026-11-02T01:00:00Z' : at,
    author: 'fixture', source: 'fixture', snapshot_id: 'snapshot-fixture',
    tree_digest: digest, policy_revision: 1, images: [],
  }));
  const details = {
    service, containers: [], current_release_id: 'release-baseline',
    candidate_id: 'candidate-fixture', releases, snapshots: [], observed_state: 'running',
    health: [], capabilities: {prepare: true, deploy: true}, drift: {state: 'unchanged'},
  };
  const previews = [];
  const submissions = [];
  const operations = [];
  let denyPreview = false;
  let unexpectedRequests = 0;
  const runtimeErrors = [];
  result.runtime_errors = runtimeErrors;

  function json(response, status, value) {
    response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
    response.end(JSON.stringify(value));
  }
  async function body(request) {
    let text = '';
    for await (const chunk of request) {
      text += chunk;
      if (text.length > 65536) throw new Error('fixture_request_limit');
    }
    return JSON.parse(text);
  }
  async function handle(request, response) {
    const url = new URL(request.url, 'http://ctfm-dialog.test');
    if (request.method === 'GET' && url.pathname === '/api/auth/session') {
      return json(response, 200, {user: {id: 'fixture-admin', username: 'fixture-admin', role: 'admin', disabled: false, sensitive_access: true, created_at: at}, csrf_token: 'fixture-only-csrf', expires_at: '2099-01-01T00:00:00Z'});
    }
    if (request.method === 'GET' && url.pathname === '/api/services') return json(response, 200, [service]);
    if (request.method === 'GET' && url.pathname === '/api/services/' + service.id) return json(response, 200, details);
    if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, {executor: 'ok'});
    if (request.method === 'GET' && url.pathname === '/api/operations') return json(response, 200, operations);
    if (request.method === 'GET' && /^\/api\/operations\/operation-fixture-\d+\/events$/.test(url.pathname)) return json(response, 200, []);
    if (request.method === 'GET' && /^\/api\/operations\/operation-fixture-\d+\/diagnostics$/.test(url.pathname)) return json(response, 200, {chunks: [], bytes: 0, returned_bytes: 0, next_sequence: 0, has_more: false, dropped_bytes: 0, truncated: false});
    if (request.method === 'POST' && url.pathname === '/api/preview') {
      const input = await body(request);
      previews.push({input, csrf: request.headers['x-csrf-token']});
      result.preview_requests = previews.length;
      if (denyPreview) return json(response, 403, {code: 'fixture_preview_denied', message: 'Fixture: preview access denied'});
      return json(response, 200, {
        service_id: service.id, action: input.action, targets: ['app'], changed_files: [],
        plan_digest: 'sha256:' + String(previews.length).repeat(64).slice(0, 64),
        policy_revision: 1, current_tree_digest: digest, has_rollback: true,
        active_release_id: 'release-baseline', target_release_id: input.release_id,
        data_compatibility_required: input.action === 'deploy',
      });
    }
    if (request.method === 'POST' && url.pathname === '/api/operations') {
      const input = await body(request);
      submissions.push({input, csrf: request.headers['x-csrf-token']});
      result.mock_operation_submissions = submissions.length;
      const operation = {spec: {id: 'operation-fixture-' + submissions.length, service_id: service.id, kind: input.action, initiator: 'fixture-admin'}, state: 'succeeded', stage: 'recording', created_at: at, updated_at: at, outcome: {}};
      operations.push(operation);
      return json(response, 200, operation);
    }
    if (url.pathname.startsWith('/api/')) {
      unexpectedRequests++;
      return json(response, 404, {code: 'unexpected_fixture_request', message: 'Unexpected fixture endpoint'});
    }
    if (request.method !== 'GET') {
      unexpectedRequests++;
      response.writeHead(405).end();
      return;
    }
    const name = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
    const file = path.resolve(dist, name);
    if (!file.startsWith(dist + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile() || fs.realpathSync(file) !== file) {
      response.writeHead(404).end();
      return;
    }
    const types = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json'};
    response.writeHead(200, {'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store'});
    fs.createReadStream(file).pipe(response);
  }
  server = http.createServer((request, response) => {
    handle(request, response).catch(() => {
      if (!response.headersSent) json(response, 500, {code: 'fixture_error', message: 'Fixture request failed'});
      else response.destroy();
    });
  });
  server.on('upgrade', (request, socket) => {
    if (request.url !== '/api/stream') unexpectedRequests++;
    socket.end('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'http://ctfm-dialog.test:' + server.address().port;
  browser = await playwright.chromium.launch({headless: true, args: ['--host-resolver-rules=MAP ctfm-dialog.test 127.0.0.1', '--no-proxy-server']});
  result.browser_version = browser.version();
  context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block'});
  await context.route('**/*', route => {
    const request = new URL(route.request().url());
    if (request.origin === origin) return route.continue();
    unexpectedRequests++;
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  page.on('pageerror', error => runtimeErrors.push({name: error.name, message: error.message}));
  await page.goto(origin, {waitUntil: 'domcontentloaded'});
  const availability = await page.evaluate(() => ({secure: isSecureContext, uuid: typeof crypto.randomUUID, random: typeof crypto.getRandomValues}));
  check('http_origin_reproduces_missing_randomUUID_with_available_getRandomValues', !availability.secure && availability.uuid === 'undefined' && availability.random === 'function');
  await page.getByRole('button', {name: service.name}).first().click();

  async function open(action, label) {
    result.phase = 'open_' + action;
    const [response] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/preview' && response.request().postDataJSON().action === action),
      page.getByRole('button', {name: label, exact: true}).click(),
    ]);
    const dialog = page.getByRole('dialog');
    await dialog.waitFor({state: 'visible'});
    await dialog.locator('.loading-line').waitFor({state: 'hidden'});
    return {dialog, response};
  }
  function validKey(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 128 && /^[\x21-\x7e]+$/.test(value);
  }
  result.phase = 'prepare';
  const prepare = await open('prepare', 'Подготовить');
  const first = previews.at(-1).input;
  const firstPlan = (await prepare.response.json()).plan_digest;
  check('prepare_opens_real_preview_without_submitting', prepare.response.status() === 200 && await prepare.dialog.getByText('Изменения файлов', {exact: true}).isVisible() && validKey(first.idempotency_key) && submissions.length === 0);
  await prepare.dialog.getByRole('button', {name: 'Подготовить', exact: true}).click();
  await page.getByRole('dialog').getByText('Операция operation-fixture-1', {exact: true}).waitFor();
  check('prepare_confirmation_uses_preview_key_digest_and_csrf_once', submissions.length === 1 && submissions[0].input.idempotency_key === first.idempotency_key && submissions[0].input.plan_digest === firstPlan && submissions[0].csrf === 'fixture-only-csrf');
  await page.getByRole('dialog').getByRole('button', {name: 'Закрыть', exact: true}).last().click();

  result.phase = 'deploy';
  const deploy = await open('deploy', 'Применить');
  const deployKey = previews.at(-1).input.idempotency_key;
  check('deploy_opens_with_new_key_and_data_confirmation_gate', deploy.response.status() === 200 && validKey(deployKey) && deployKey !== first.idempotency_key && await deploy.dialog.getByRole('button', {name: 'Применить', exact: true}).isDisabled());
  result.phase = 'select_release';
  const [changed] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/api/preview' && response.request().postDataJSON().release_id === 'release-first'),
    deploy.dialog.getByRole('combobox').selectOption('release-first'),
  ]);
  const changedPlan = (await changed.json()).plan_digest;
  await deploy.dialog.locator('.loading-line').waitFor({state: 'hidden'});
  const latest = previews.at(-1).input;
  check('release_change_preserves_key_and_refreshes_plan', latest.idempotency_key === deployKey && latest.release_id === 'release-first' && changedPlan !== (await deploy.response.json()).plan_digest);
  await deploy.dialog.getByRole('checkbox').check();
  check('local_confirmation_rerender_preserves_key_and_does_not_submit', submissions.length === 1 && previews.at(-1).input.idempotency_key === deployKey && await deploy.dialog.getByRole('button', {name: 'Применить', exact: true}).isEnabled());
  await deploy.dialog.getByRole('button', {name: 'Применить', exact: true}).click();
  await page.getByRole('dialog').getByText('Операция operation-fixture-2', {exact: true}).waitFor();
  check('deploy_confirmation_uses_same_key_current_plan_and_release_once', submissions.length === 2 && submissions[1].input.idempotency_key === deployKey && submissions[1].input.plan_digest === changedPlan && submissions[1].input.release_id === 'release-first' && submissions[1].input.confirm_data_compatibility === true && submissions[1].csrf === 'fixture-only-csrf');
  await page.getByRole('dialog').getByRole('button', {name: 'Закрыть', exact: true}).last().click();

  denyPreview = true;
  const denied = await open('prepare', 'Подготовить');
  const alert = denied.dialog.getByRole('alert');
  await alert.waitFor({state: 'visible'});
  check('reopening_creates_new_key_and_preview_error_stays_in_visible_dialog', denied.response.status() === 403 && previews.at(-1).input.idempotency_key !== first.idempotency_key && (await alert.textContent()) === 'Fixture: preview access denied' && await denied.dialog.getByRole('button', {name: 'Подготовить', exact: true}).isDisabled() && submissions.length === 2);
  await denied.dialog.getByRole('button', {name: 'Отмена', exact: true}).click();
  check('no_runtime_errors_or_external_network_or_unexpected_requests', runtimeErrors.length === 0 && unexpectedRequests === 0 && submissions.length === 2);
  result.preview_requests = previews.length;
  result.mock_operation_submissions = submissions.length;
  result.passed = true;
  result.phase = 'complete';
}

main().catch(error => {
  result.error = {name: error.name, message: error.message};
  process.exitCode = 1;
}).finally(async () => {
  if (context) await context.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  if (server) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  console.log(JSON.stringify(result, null, 2));
});
