#!/usr/bin/env node
'use strict';

// Companion to directory_picker_process_smoke.py. Uses real APIs and fresh
// browser state; never writes passwords, cookies, HAR, screenshots or traces.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const result = {passed: false, launched: false, checks: [], scope: {
  headless: true, temporary_profile: true, actual_directory_api: true,
  api_mocking: false, docker_used: false, containers_registered: false,
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
  let playwright;
  try {
    playwright = require('playwright');
  } catch {
    const cached = path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
    if (!fs.existsSync(cached)) {
      result.unavailable = 'cached_playwright_unavailable_no_install_attempted';
      return;
    }
    playwright = require(cached);
  }
  if (!fs.existsSync(playwright.chromium.executablePath())) {
    result.unavailable = 'cached_chromium_unavailable_no_install_attempted';
    return;
  }
  browser = await playwright.chromium.launch({headless: true});
  result.launched = true;
  result.browser_version = browser.version();
  context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  let browseResponses = 0;
  let unexpectedRequests = 0;
  let mutationRequests = 0;
  const runtimeErrors = [];
  page.on('pageerror', error => runtimeErrors.push(String(error.name || 'Error')));
  page.on('request', request => {
    const target = new URL(request.url());
    if (target.origin !== origin.origin && !(target.protocol === 'ws:' && target.host === origin.host)) unexpectedRequests++;
    if (/^\/api\/registration\/(inspect|proposals|approve)$/.test(target.pathname)) mutationRequests++;
  });
  page.on('response', response => {
    if (new URL(response.url()).pathname === '/api/registration/directories' && response.status() === 200) browseResponses++;
  });
  result.phase = 'login';
  await page.goto(origin.origin, {waitUntil: 'domcontentloaded'});
  await page.getByLabel('Имя пользователя', {exact: true}).fill(input.username);
  await page.getByLabel('Пароль', {exact: true}).fill(input.password);
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await page.getByRole('button', {name: 'Добавить сервис', exact: true}).first().click();
  const dialog = page.getByRole('dialog');
  const field = dialog.getByLabel('Путь к сервису', {exact: true});
  const trigger = dialog.getByRole('button', {name: 'Выбрать папку', exact: true});
  const picker = dialog.locator('#registration-directory-picker');
  const folder = name => picker.getByRole('button', {name: 'Открыть папку ' + name, exact: true});
  const current = expected => picker.locator('.directory-picker-location > code').filter({hasText: expected});
  const waitCurrent = async expected => {
    await picker.locator('.directory-picker-location > code').filter({hasText: expected}).waitFor();
    await picker.locator('[role="status"]').waitFor({state: 'hidden'});
    check('location_' + result.phase, (await current(expected).textContent()) === expected);
  };
  check('actual_admin_ui_opens_registration', await field.isVisible());
  await trigger.click();
  result.phase = 'root_list';
  await folder('games').waitFor();
  check('approved_roots_render_from_actual_executor', (await picker.locator('.directory-picker-list li').count()) === 1);
  check('root_list_cannot_be_selected_as_a_directory', await picker.getByRole('button', {name: 'Выбрать эту папку', exact: true}).isDisabled());
  check('inspection_disabled_while_browsing', await dialog.getByRole('button', {name: 'Найти сервис', exact: true}).isDisabled());
  await folder('games').click();
  result.phase = 'approved_root';
  await waitCurrent(input.root);
  await folder('service').waitFor();
  check('real_child_directories_are_listed', await folder('service').isVisible() && await folder('empty').isVisible());
  check('symbolic_links_and_regular_files_not_offered', await folder('linked-service').count() === 0 && await folder('ordinary-file.txt').count() === 0 && await folder('external-only').count() === 0);
  check('navigation_cannot_go_above_approved_root', await picker.getByRole('button', {name: 'Выше', exact: true}).isDisabled());
  await folder('service').click();
  result.phase = 'service_directory';
  await waitCurrent(input.service);
  await picker.locator('.directory-picker-compose > code').waitFor();
  check('common_compose_filename_hint_visible', (await picker.locator('.directory-picker-compose > code').textContent()) === 'compose.yaml');
  await folder('components').click();
  result.phase = 'nested_directory';
  await waitCurrent(input.service + '/components');
  check('empty_directory_feedback_visible', await picker.getByText('Вложенных папок нет.', {exact: true}).isVisible());
  await picker.getByRole('button', {name: 'Выше', exact: true}).click();
  result.phase = 'return_to_service';
  await waitCurrent(input.service);
  await picker.getByRole('button', {name: 'Выбрать эту папку', exact: true}).click();
  await picker.waitFor({state: 'hidden'});
  check('selected_server_directory_populates_manual_field', await field.inputValue() === input.service);
  check('selection_restores_inspection_and_keyboard_focus', await dialog.getByRole('button', {name: 'Найти сервис', exact: true}).isEnabled() && await trigger.evaluate(element => element === document.activeElement));
  await trigger.click();
  result.phase = 'reopen_selection';
  await waitCurrent(input.service);
  await picker.getByRole('button', {name: 'Выше', exact: true}).click();
  result.phase = 'parent_navigation';
  await waitCurrent(input.root);
  await picker.getByRole('button', {name: 'Все каталоги', exact: true}).click();
  result.phase = 'return_to_roots';
  await folder('games').waitFor();
  check('return_to_root_list_does_not_change_manual_selection', await field.inputValue() === input.service);
  await picker.getByRole('button', {name: 'Отмена', exact: true}).click();
  await picker.waitFor({state: 'hidden'});
  check('cancel_preserves_selected_path', await field.inputValue() === input.service);
  await field.fill(input.empty);
  await trigger.click();
  result.phase = 'manual_empty_directory';
  await waitCurrent(input.empty);
  check('manual_input_used_as_browser_start', await picker.getByText('Вложенных папок нет.', {exact: true}).isVisible());
  await field.fill(input.service);
  await picker.waitFor({state: 'hidden'});
  check('typing_manually_closes_browser_without_replacing_input', await field.inputValue() === input.service);
  await field.fill(input.root + '/missing-directory');
  await trigger.click();
  result.phase = 'unavailable_directory';
  await picker.getByRole('alert').waitFor();
  check('unavailable_folder_shows_real_error_and_blocks_selection', await picker.getByRole('alert').isVisible() && await picker.getByRole('button', {name: 'Выбрать эту папку', exact: true}).isDisabled());
  await picker.getByRole('button', {name: 'Повторить', exact: true}).click();
  await picker.getByRole('alert').waitFor();
  await picker.getByRole('button', {name: 'Все каталоги', exact: true}).click();
  result.phase = 'recover_to_roots';
  await folder('games').waitFor();
  check('error_recovery_keeps_manual_input', await field.inputValue() === input.root + '/missing-directory');
  await picker.getByRole('button', {name: 'Закрыть выбор папки', exact: true}).click();
  await picker.waitFor({state: 'hidden'});
  await field.fill(input.empty);
  await page.setViewportSize({width: 520, height: 900});
  await trigger.click();
  result.phase = 'narrow_viewport';
  await waitCurrent(input.empty);
  check('picker_contents_fit_narrow_viewport', await picker.evaluate(element => element.scrollWidth <= element.clientWidth + 1));
  await picker.getByRole('button', {name: 'Выбрать эту папку', exact: true}).click();
  await picker.waitFor({state: 'hidden'});
  check('narrow_viewport_selection_works', await field.inputValue() === input.empty);
  await dialog.getByRole('button', {name: 'Закрыть', exact: true}).click();
  await dialog.waitFor({state: 'hidden'});
  await page.getByRole('button', {name: 'Добавить сервис', exact: true}).first().click();
  check('new_registration_has_no_previous_selection', await page.getByRole('dialog').getByLabel('Путь к сервису', {exact: true}).inputValue() === '');
  check('real_directory_api_used_without_mocking', browseResponses >= 10);
  check('browsing_did_not_inspect_or_register_containers', mutationRequests === 0);
  check('no_javascript_runtime_exceptions', runtimeErrors.length === 0);
  check('browser_requests_stayed_on_fixture_origin', unexpectedRequests === 0);
  result.passed = true;
  delete result.phase;
}

main().catch(error => {
  result.error_type = String(error.name || 'Error');
  result.failed_check = result.checks.find(value => !value.passed)?.name || 'browser_step_failed';
  process.exitCode = 1;
}).finally(async () => {
  try { if (context) await context.close(); } finally { if (browser) await browser.close(); }
  result.browser_closed = true;
  process.stdout.write(JSON.stringify(result) + '\n');
});
