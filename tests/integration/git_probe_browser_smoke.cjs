#!/usr/bin/env node
'use strict';

// UI contract companion: real dashboard, bounded fake Unix executor. No GitHub
// requests, browser interception, credentials in reports, screenshots or traces.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const result = {passed: false, launched: false, checks: [], scope: {
  actual_dashboard: true, executor_protocol_fixture: true,
  real_git_transport: false, browser_api_interception: false,
  external_network: false, settings_saved: false,
  screenshots: false, traces: false,
}};
let browser;
let context;

function check(name, condition) {
  result.checks.push({name, passed: Boolean(condition)});
  if (!condition) throw new Error(name);
}

async function main() {
  const raw = fs.readFileSync(0, 'utf8');
  if (raw.length > 16384) throw new Error('fixture_context_too_large');
  const input = JSON.parse(raw);
  const origin = new URL(input.origin);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || !origin.port ||
      origin.pathname !== '/' || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error('only_private_loopback_fixture_origin_permitted');
  }
  if (!/^\/(?:private\/)?tmp\/ctfm-git-ui-[^/]+\/executor[.]sock$/.test(input.executor_socket)) throw new Error('only_disposable_executor_fixture_socket_permitted');
  // Test-only ordering: observe the fake executor entering its delayed handler
  // before editing. No browser route is intercepted and no production route is
  // added; otherwise an immediate abort could precede server-side execution.
  const fixtureStatus = () => new Promise((resolve, reject) => {
    const request = http.request({socketPath: input.executor_socket, path: '/v1/fixture/status', method: 'GET'}, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', part => { body += part; if (body.length > 4096) request.destroy(new Error('fixture_status_oversized')); });
      response.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(new Error('fixture_status_invalid')); } });
      response.on('error', reject);
    });
    request.setTimeout(1000, () => request.destroy(new Error('fixture_status_timeout')));
    request.on('error', reject);
    request.end();
  });
  let playwright;
  try { playwright = require('playwright'); } catch {
    const cached = path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
    if (!fs.existsSync(cached)) { result.unavailable = 'cached_playwright_unavailable_no_install_attempted'; return; }
    playwright = require(cached);
  }
  if (!fs.existsSync(playwright.chromium.executablePath())) { result.unavailable = 'cached_chromium_unavailable_no_install_attempted'; return; }
  browser = await playwright.chromium.launch({headless: true});
  result.launched = true;
  result.browser_version = browser.version();
  context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const runtimeErrors = [];
  let externalRequests = 0;
  let mutationRequests = 0;
  page.on('pageerror', error => runtimeErrors.push(String(error.name || 'Error')));
  page.on('request', request => {
    const target = new URL(request.url());
    if (target.origin !== origin.origin && !(target.protocol === 'ws:' && target.host === origin.host)) externalRequests++;
    if (/^\/api\/(?:registration\/(?:proposals|approve)|services\/[^/]+\/source|operations)$/.test(target.pathname) && request.method() === 'POST') mutationRequests++;
  });
  result.phase = 'login';
  await page.goto(origin.origin, {waitUntil: 'domcontentloaded'});
  await page.getByLabel('Имя пользователя', {exact: true}).fill(input.username);
  await page.getByLabel('Пароль', {exact: true}).fill(input.password);
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await page.getByRole('button', {name: 'Добавить сервис', exact: true}).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Путь к сервису', {exact: true}).fill(input.service);
  await dialog.getByRole('button', {name: 'Найти сервис', exact: true}).click();
  await dialog.getByRole('checkbox', {name: /Подключить GitHub/}).check();
  const url = dialog.getByLabel(/^Git URL/);
  const ref = dialog.getByLabel('Ветка, тег или commit', {exact: true});
  const subdirectory = dialog.getByRole('textbox', {name: /^Подкаталог сервиса/});
  const token = dialog.getByLabel(/^Токен ·/);
  const probe = dialog.getByRole('region', {name: 'Проверка Git-репозитория', exact: true});
  const button = probe.getByRole('button', {name: 'Проверить подключение', exact: true});
  const branch = probe.getByLabel(/^Выбрать ветку/);
  const directories = probe.getByRole('region', {name: 'Папки Git-репозитория', exact: true});
  const good = probe.getByText('Подключение и версия проверены', {exact: true});
  const warning = probe.getByText('Репозиторий доступен · уточните версию', {exact: true});
  const probeResponse = () => page.waitForResponse(response => new URL(response.url()).pathname === '/api/git/probe' && response.request().method() === 'POST');
  const submit = async expectedStatus => {
    const response = probeResponse();
    await button.click();
    check('http_status_' + result.phase, (await response).status() === expectedStatus);
  };
  const beginDelayedProbe = async () => {
    const before = (await fixtureStatus()).delayed_probes;
    await button.click();
    const deadline = Date.now() + 2000;
    while (Date.now() < deadline) {
      if ((await fixtureStatus()).delayed_probes > before) return;
      await page.waitForTimeout(20);
    }
    throw new Error('delayed_fixture_handler_not_entered');
  };
  check('stage_two_contains_explicit_probe_without_registration', await button.isVisible() && await button.isDisabled());
  await url.fill('https://github.com/fixture/game.git');
  result.phase = 'default_ref';
  await submit(200);
  await good.waitFor();
  check('default_branch_and_git_sha_displayed', await probe.getByText('main', {exact: true}).count() > 0 && await probe.getByText('a'.repeat(40), {exact: true}).isVisible());
  check('advertised_branch_choices_available', await branch.locator('option[value="refs/heads/main"]').count() === 1 && await branch.locator('option[value="refs/heads/feature/next"]').count() === 1);
  result.phase = 'choose_git_directory';
  await directories.getByRole('button', {name: 'Открыть папку vuln-service', exact: true}).click();
  await directories.getByRole('button', {name: 'Выбрать эту папку', exact: true}).click();
  check('directory_selection_fills_relative_path', await subdirectory.inputValue() === 'vuln-service');
  await directories.getByRole('button', {name: 'Использовать корень', exact: true}).click();
  check('root_selection_clears_relative_path', await subdirectory.inputValue() === '');
  await directories.getByRole('button', {name: 'Открыть папку vuln-service', exact: true}).click();
  const previousDirectoryRequests = (await fixtureStatus()).delayed_directories;
  await directories.getByRole('button', {name: 'Открыть папку web', exact: true}).click();
  const deadline = Date.now() + 2000;
  while ((await fixtureStatus()).delayed_directories === previousDirectoryRequests) {
    if (Date.now() >= deadline) throw new Error('delayed_directory_handler_not_entered');
    await page.waitForTimeout(20);
  }
  await branch.selectOption('refs/heads/feature/next');
  check('branch_selection_sets_full_ref_and_invalidates_old_check', await ref.inputValue() === 'refs/heads/feature/next' && await good.count() === 0);
  check('branch_choices_survive_interactive_selection', await branch.isVisible());
  await directories.getByRole('button', {name: 'Открыть папку alternate', exact: true}).waitFor();
  await page.waitForTimeout(1100);
  check('new_branch_folders_replace_an_in_flight_old_directory',
    await directories.getByRole('button', {name: 'Открыть папку alternate', exact: true}).isVisible() &&
    await directories.getByText('vuln-service/web', {exact: true}).count() === 0);
  result.phase = 'chosen_branch';
  await submit(200);
  await good.waitFor();
  check('chosen_branch_gets_new_sha', await probe.getByText('b'.repeat(40), {exact: true}).isVisible());
  await ref.fill('missing');
  result.phase = 'missing_ref';
  await submit(200);
  await warning.waitFor();
  check('missing_ref_does_not_show_green_success', await good.count() === 0 && await probe.getByText(/не найдены среди опубликованных версий/).isVisible());
  await ref.fill('release');
  result.phase = 'ambiguous_ref';
  await submit(200);
  await warning.waitFor();
  check('ambiguous_ref_requires_explicit_choice', await good.count() === 0 && await probe.getByText(/неоднозначно/).isVisible());
  await ref.fill('c'.repeat(40));
  result.phase = 'unadvertised_sha';
  await submit(200);
  await warning.waitFor();
  check('unadvertised_sha_is_not_claimed_verified', await good.count() === 0 && await probe.getByText(/наличие указанного SHA нельзя подтвердить/).isVisible());
  await ref.fill('HEAD');
  await token.fill(input.invalid_token);
  result.phase = 'bad_credentials';
  await submit(502);
  await probe.getByRole('alert').waitFor();
  check('authentication_failure_is_actionable_and_redacted', await probe.getByText(/Проверьте Git URL, пользователя, токен/).isVisible() && !(await dialog.textContent()).includes(input.invalid_token));
  await token.fill(input.token);
  result.phase = 'retry_credentials';
  await submit(200);
  await good.waitFor();
  check('corrected_credentials_can_be_checked_again', await branch.isVisible() && !(await dialog.textContent()).includes(input.token));
  await url.fill('https://github.com/fixture/slow.git');
  result.phase = 'edit_token_in_flight';
  await beginDelayedProbe();
  await token.fill(input.invalid_token);
  await page.waitForTimeout(2700);
  check('late_reply_after_token_edit_cannot_restore_success_or_branches', await good.count() === 0 && await branch.count() === 0 && await probe.getByRole('alert').count() === 0 && await button.isEnabled());
  await token.fill(input.token);
  result.phase = 'edit_url_in_flight';
  await beginDelayedProbe();
  await url.fill('https://github.com/fixture/changed.git');
  await page.waitForTimeout(2700);
  check('late_reply_after_url_edit_cannot_restore_old_result', await good.count() === 0 && await branch.count() === 0 && await button.isEnabled());
  result.phase = 'new_url';
  await submit(200);
  await good.waitFor();
  check('new_url_can_be_checked_independently', await branch.isVisible());
  await url.fill('https://github.com/fixture/empty.git');
  result.phase = 'empty_repository';
  await submit(200);
  await warning.waitFor();
  check('empty_repository_has_no_fabricated_branch_or_success', await good.count() === 0 && await branch.count() === 0 && await probe.getByText('Опубликованных веток нет.', {exact: true}).isVisible());
  await url.fill('https://github.com/fixture/many.git');
  result.phase = 'truncated_branches';
  await submit(200);
  await good.waitFor();
  check('truncated_branch_advertisement_is_explicit', await probe.getByText(/Показана только часть веток/).isVisible());
  await page.setViewportSize({width: 520, height: 900});
  check('probe_fits_narrow_viewport', await probe.evaluate(element => element.scrollWidth <= element.clientWidth + 1));
  await url.fill('https://github.com/fixture/slow.git');
  result.phase = 'close_in_flight';
  await beginDelayedProbe();
  await dialog.getByRole('button', {name: 'Закрыть', exact: true}).click();
  await dialog.waitFor({state: 'hidden'});
  await page.waitForTimeout(2700);
  check('closing_in_flight_unmounts_probe_cleanly', await page.getByRole('region', {name: 'Проверка Git-репозитория', exact: true}).count() === 0);
  check('probe_did_not_save_or_register_a_service', mutationRequests === 0);
  check('browser_network_stayed_on_local_fixture', externalRequests === 0);
  check('no_javascript_runtime_errors', runtimeErrors.length === 0);
  result.passed = true;
  delete result.phase;
}

main().catch(error => {
  result.error_type = String(error.name || 'Error');
  result.failed_check = result.checks.find(check => !check.passed)?.name || 'browser_step_failed';
  process.exitCode = 1;
}).finally(async () => {
  try { if (context) await context.close(); } finally { if (browser) await browser.close(); }
  result.browser_closed = true;
  process.stdout.write(JSON.stringify(result) + '\n');
});
