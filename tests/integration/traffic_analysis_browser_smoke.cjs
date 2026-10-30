#!/usr/bin/env node
'use strict';

// Optional UI companion to traffic_analysis_process_smoke.py. Credentials arrive
// only on stdin, and the browser uses a fresh disposable profile. No snapshots,
// HAR, traces, screenshots, passwords or traffic payloads are written to disk.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const result = {launched: false, passed: false, unavailable: false, checks: [],
  scope: {headless: true, temporary_profile: true, real_analysis_api: true,
    screenshots: false, traces: false, system_ca_changed: false,
    descriptor_upload_tested: false, unrelated_missing_docker_errors_expected: true}};
let browser;
let context;

function check(name, condition) {
  result.checks.push({name, passed: Boolean(condition)});
  if (!condition) throw new Error(name);
}

async function main() {
  const raw = fs.readFileSync(0, 'utf8');
  if (raw.length > 3 * 1024 * 1024) throw new Error('fixture_context_too_large');
  const input = JSON.parse(raw);
  const origin = new URL(input.origin);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || !origin.port ||
      origin.pathname !== '/' || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error('only_private_loopback_fixture_origin_permitted');
  }
  let playwright;
  try {
    playwright = require('playwright');
  } catch {
    const cached = path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
    if (!fs.existsSync(cached)) {
      result.unavailable = true;
      result.reason = 'cached_playwright_unavailable_no_install_attempted';
      return;
    }
    playwright = require(cached);
  }
  if (!fs.existsSync(playwright.chromium.executablePath())) {
    result.unavailable = true;
    result.reason = 'cached_chromium_unavailable_no_install_attempted';
    return;
  }
  browser = await playwright.chromium.launch({headless: true});
  result.launched = true;
  result.browser_version = browser.version();
  context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(12000);
  const runtimeErrors = [];
  const analysisFailures = [];
  const unexpectedRequests = [];
  page.on('pageerror', error => runtimeErrors.push(String(error.name || 'Error')));
  page.on('request', request => {
    const target = new URL(request.url());
    if (target.origin !== origin.origin && !(target.protocol === 'ws:' && target.host === origin.host)) {
      unexpectedRequests.push(target.protocol + '//' + target.hostname);
    }
  });
  page.on('response', response => {
    const target = new URL(response.url());
    if (/^\/api\/(flows|descriptors)(?:[/?]|$)/.test(target.pathname) && response.status() >= 400) {
      analysisFailures.push({path: target.pathname, status: response.status()});
    }
  });
  await page.goto(origin.origin, {waitUntil: 'domcontentloaded'});
  await page.getByLabel('Имя пользователя', {exact: true}).fill(input.username);
  await page.getByLabel('Пароль', {exact: true}).fill(input.password);
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await page.getByRole('button', {name: 'Трафик', exact: true}).waitFor();
  check('actual_ui_login_and_workspace', true);
  await page.getByRole('button', {name: 'Трафик', exact: true}).click();
  await page.getByRole('tab', {name: 'TCP-потоки / gRPC', exact: true}).click();
  await page.getByRole('heading', {name: 'TCP-потоки и UDP', exact: true}).waitFor();
  const row = page.locator('tbody tr').filter({hasText: ':' + input.knownPort});
  await row.waitFor();
  check('real_flows_tab_lists_known_synthetic_tcp_conversation', await row.count() === 1);
  check('gaps_and_overlap_limits_notice_visible', await page.getByText(/пропуски не склеиваются, конфликтующие перекрытия отмечаются/).isVisible());
  await row.getByRole('button', {name: /^Открыть поток /}).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByRole('heading', {name: 'A → B', exact: true}).waitFor();
  await dialog.getByRole('heading', {name: 'B → A', exact: true}).waitFor();
  check('raw_flow_dialog_renders_both_tcp_directions', true);
  const chunks = dialog.locator('summary').filter({hasText: /^Блок offset /});
  check('both_contiguous_direction_chunks_present', await chunks.count() === 2);
  for (const chunk of await chunks.all()) await chunk.click();
  check('raw_hex_ascii_views_render_captured_bytes', await dialog.locator('pre.packet-hex').count() === 2 &&
    (await dialog.locator('pre.packet-hex').allTextContents()).every(value => value.length > 20));
  const selector = dialog.locator('label').filter({hasText: 'Protobuf descriptor'}).locator('select');
  result.phase = 'select_existing_descriptor';
  await selector.locator('option[value="' + input.descriptorID + '"]').waitFor({state: 'attached'});
  await selector.selectOption(input.descriptorID);
  result.phase = 'decode_selected_descriptor';
  await dialog.getByRole('button', {name: 'Разобрать HTTP/2 / gRPC', exact: true}).click();
  await dialog.getByRole('heading', {name: '/demo.Echo/Chat', exact: true}).waitFor();
  const requestMessage = dialog.locator('summary').filter({hasText: /demo\.Request/});
  const responseMessage = dialog.locator('summary').filter({hasText: /demo\.Response/});
  await requestMessage.waitFor();
  result.phase = 'expand_named_protobuf_messages';
  await requestMessage.click();
  await responseMessage.click();
  const decoded = await dialog.locator('pre.packet-hex').allTextContents();
  check('protobuf_named_request_and_response_json_render', decoded.some(value => value.includes('"name": "alice"')) &&
    decoded.some(value => value.includes('"ok": true')));
  check('grpc_success_status_and_streaming_metadata_render', await dialog.getByText('gRPC status 0', {exact: true}).isVisible() &&
    await dialog.getByText('Client streaming / Server streaming', {exact: true}).isVisible());
  await dialog.getByRole('button', {name: 'Закрыть', exact: true}).first().click();
  await page.getByRole('button', {name: 'Descriptors', exact: true}).click();
  result.phase = 'open_admin_descriptor_inventory';
  dialog = page.getByRole('dialog');
  await dialog.getByRole('heading', {name: 'Protobuf descriptors', exact: true}).waitFor();
  const inventory = dialog.locator('summary').filter({hasText: input.descriptorID});
  await inventory.waitFor();
  await inventory.click();
  check('admin_existing_descriptor_inventory_handles_metadata_only_methods', await dialog.getByText(/1 методов/).isVisible());
  await dialog.getByRole('button', {name: 'Закрыть', exact: true}).first().click();
  await page.getByRole('tab', {name: 'Пакеты TCP / UDP', exact: true}).click();
  result.phase = 'packets_tab';
  await page.getByRole('heading', {name: 'Пакеты TCP / UDP', exact: true}).waitFor();
  await page.locator('tbody tr').first().waitFor();
  check('packets_tab_renders_real_archive_metadata', await page.locator('tbody tr').count() === 24);
  await page.getByRole('tab', {name: 'TCP-потоки / gRPC', exact: true}).click();
  await page.getByRole('heading', {name: 'TCP-потоки и UDP', exact: true}).waitFor();
  await page.locator('tbody tr').filter({hasText: ':' + input.knownPort}).waitFor();
  check('return_to_flows_preserves_working_navigation', true);
  check('analysis_ui_has_no_javascript_runtime_exceptions', runtimeErrors.length === 0);
  check('analysis_api_calls_succeed_without_mocking', analysisFailures.length === 0);
  check('browser_requests_stay_on_private_fixture_origin', unexpectedRequests.length === 0);
  result.passed = true;
  delete result.phase;
}

main().catch(error => {
  result.error_type = String(error.name || 'Error');
  // Assertion names are authored strings. Playwright call logs can contain
  // inputs and source excerpts, so never print exception messages or stacks.
  result.failed_check = result.checks.find(value => !value.passed)?.name || 'browser_step_failed';
  process.exitCode = 1;
}).finally(async () => {
  try { if (context) await context.close(); } finally { if (browser) await browser.close(); }
  result.browser_closed = true;
  process.stdout.write(JSON.stringify(result) + '\n');
});
