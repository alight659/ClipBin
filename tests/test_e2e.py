import socket
import threading
import time
import uuid
import urllib.request
import urllib.error
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from app import app

HOST = "127.0.0.1"


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


PORT = _free_port()
BASE = f"http://{HOST}:{PORT}"


def _wait_for_server(url, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except urllib.error.URLError:
            time.sleep(0.2)
    raise RuntimeError("server did not start in time")


@pytest.fixture(scope="session", autouse=True)
def server():
    t = threading.Thread(
        target=lambda: app.run(host=HOST, port=PORT, use_reloader=False, threaded=True),
        daemon=True,
    )
    t.start()
    _wait_for_server(BASE + "/")
    yield


@pytest.fixture()
def driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,1024")
    d = webdriver.Chrome(options=opts)
    d.implicitly_wait(0)
    yield d
    d.quit()


def wait_visible(driver, by, value, timeout=20):
    return WebDriverWait(driver, timeout).until(EC.visibility_of_element_located((by, value)))


def unique(prefix):
    return f"{prefix}{uuid.uuid4().hex[:2]}"


def test_home_form(driver):
    driver.get(BASE + "/")
    assert driver.find_element(By.NAME, "clip_name")
    assert driver.find_element(By.NAME, "clip_text")
    assert driver.find_element(By.NAME, "clip_file")
    assert driver.find_element(By.NAME, "clip_alias")
    assert driver.find_element(By.NAME, "clip_passwd")
    assert driver.find_element(By.NAME, "clip_delete")
    assert driver.find_element(By.NAME, "clip_disp")
    assert driver.find_element(By.XPATH, "//button[text()='Save']")


def test_flow_without_password_base(driver):
    alias = unique("thisalias")
    driver.get(BASE + "/")
    driver.find_element(By.NAME, "clip_name").send_keys("Test Name")
    driver.find_element(By.NAME, "clip_text").send_keys("Sample Text for test")
    driver.find_element(By.NAME, "clip_alias").send_keys(alias)
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.TAG_NAME, "code")

    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Test Name"
    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Sample Text for test"
    assert driver.current_url == BASE + "/" + alias
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Download']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='New']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Raw']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Copy']")


def test_flow_with_password(driver):
    driver.get(BASE + "/")
    driver.find_element(By.NAME, "clip_name").send_keys("Password Protected")
    driver.find_element(By.NAME, "clip_text").send_keys("Password Protected Content")
    driver.find_element(By.NAME, "clip_passwd").send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.ID, "clip_passwd")

    driver.find_element(By.NAME, "clip_passwd").send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Go']").click()

    wait_visible(driver, By.TAG_NAME, "code")

    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Password Protected"
    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Password Protected Content"


def test_flow_with_incorrect_password(driver):
    driver.get(BASE + "/")
    driver.find_element(By.NAME, "clip_name").send_keys("Password Protected")
    driver.find_element(By.NAME, "clip_text").send_keys("Password Protected Content for Incorrec")
    driver.find_element(By.NAME, "clip_passwd").send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.TAG_NAME, "input")

    driver.find_element(By.NAME, "clip_passwd").send_keys("pincorrectassword")
    driver.find_element(By.XPATH, "//button[text()='Go']").click()

    wait_visible(driver, By.XPATH, "//p[normalize-space()='Incorrect Password!']")

    assert driver.find_element(By.XPATH, "//button[text()='Go']")


def test_flow_empty(driver):
    driver.get(BASE + "/")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.TAG_NAME, "h1")

    p = driver.find_element(By.TAG_NAME, "p")
    assert p.text == "Text Field or File Cannot be Empty!"


def test_flow_user(driver):
    username = unique("user")
    driver.delete_all_cookies()
    driver.get(BASE + "/")
    driver.find_element(By.LINK_TEXT, "Login").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/login"

    driver.find_element(By.LINK_TEXT, "Register").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/register"

    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.NAME, "password_confirm").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    wait_visible(driver, By.TAG_NAME, "h2")

    driver.get(BASE + "/login")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    wait_visible(driver, By.TAG_NAME, "h1")
    assert driver.current_url == BASE + "/"

    assert driver.find_element(By.XPATH, f"//button[normalize-space()='{username}']")
    assert driver.find_element(By.NAME, "clip_edit")


def test_flow_complete_edited(driver):
    username = unique("user")
    driver.delete_all_cookies()
    driver.get(BASE + "/")
    driver.find_element(By.LINK_TEXT, "Login").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/login"

    driver.find_element(By.LINK_TEXT, "Register").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/register"

    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.NAME, "password_confirm").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    wait_visible(driver, By.TAG_NAME, "h2")

    driver.get(BASE + "/login")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    wait_visible(driver, By.TAG_NAME, "h1")
    assert driver.find_element(By.XPATH, f"//button[normalize-space()='{username}']")
    assert driver.current_url == BASE + "/"

    driver.find_element(By.NAME, "clip_name").send_keys("Test Name edited")
    driver.find_element(By.NAME, "clip_text").send_keys("Sample Text for test")
    driver.find_element(By.CSS_SELECTOR, "label[for='clip_edit']").click()
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.ID, "clip_text")

    clip_text_updated = driver.find_element(By.TAG_NAME, "textarea")
    clip_text_updated.clear()
    clip_text_updated.send_keys("This text was updated.")
    driver.find_element(By.XPATH, "//button[normalize-space()='Update']").click()

    wait_visible(driver, By.TAG_NAME, "p")

    update_confirm = driver.find_element(By.TAG_NAME, "p")
    assert update_confirm.text == "Clip has been updated"


def test_flow_dashboard(driver):
    username = unique("user")
    driver.delete_all_cookies()
    driver.get(BASE + "/")
    driver.find_element(By.LINK_TEXT, "Login").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/login"

    driver.find_element(By.LINK_TEXT, "Register").click()

    wait_visible(driver, By.TAG_NAME, "h2")
    assert driver.current_url == BASE + "/register"

    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.NAME, "password_confirm").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    wait_visible(driver, By.TAG_NAME, "h2")

    driver.get(BASE + "/login")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys("password1")
    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    wait_visible(driver, By.NAME, "clip_name")
    assert driver.current_url == BASE + "/"

    driver.find_element(By.NAME, "clip_name").send_keys("Dash Test")
    driver.find_element(By.NAME, "clip_text").send_keys("Sample Text for Dash test")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    wait_visible(driver, By.TAG_NAME, "h1")

    driver.find_element(By.XPATH, f"//button[normalize-space()='{username}']").click()
    driver.find_element(By.LINK_TEXT, "Dashboard").click()

    wait_visible(driver, By.TAG_NAME, "table")
    assert driver.current_url == BASE + "/dashboard"

    verify_name_in_table = driver.find_element(By.TAG_NAME, "td")
    assert verify_name_in_table.text == "Dash Test"

    driver.find_element(By.LINK_TEXT, "Go").click()

    wait_visible(driver, By.TAG_NAME, "code")

    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Dash Test"

    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Sample Text for Dash test"

    driver.get(BASE + "/dashboard")
    driver.find_element(By.LINK_TEXT, "Delete").click()

    wait_visible(driver, By.TAG_NAME, "h1")

    assert driver.find_element(By.LINK_TEXT, "Start Creating?")
