import threading
import time
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from app import app

HOST = "127.0.0.1"
PORT = 5005
BASE = f"http://{HOST}:{PORT}"


@pytest.fixture(scope="session", autouse=True)
def server():
    t = threading.Thread(target=lambda: app.run(host=HOST, port=PORT, use_reloader=False))
    t.daemon = True
    t.start()
    time.sleep(1)
    yield


@pytest.fixture()
def driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    d = webdriver.Chrome(options=opts)
    yield d
    d.quit()


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
    driver.get(BASE + "/")
    clip_name = driver.find_element(By.NAME, "clip_name")
    clip_name.send_keys("Test Name")
    clip_text = driver.find_element(By.NAME, "clip_text")
    clip_text.send_keys("Sample Text for test")
    clip_alias = driver.find_element(By.NAME, "clip_alias")
    clip_alias.send_keys("thisalias")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "code"))
    )
    
    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Test Name"
    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Sample Text for test"
    assert driver.current_url == BASE + "/thisalias"
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Download']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='New']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Raw']")
    assert driver.find_element(By.XPATH, "//button[normalize-space()='Copy']")


def test_flow_with_password(driver):
    driver.get(BASE + "/")
    clip_name = driver.find_element(By.NAME, "clip_name")
    clip_name.send_keys("Password Protected")
    clip_text = driver.find_element(By.NAME, "clip_text")
    clip_text.send_keys("Password Protected Content")
    clip_passwd = driver.find_element(By.NAME, "clip_passwd")
    clip_passwd.send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "input"))
    )
    
    clip_view_passwd = driver.find_element(By.NAME, "clip_passwd")
    clip_view_passwd.send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Go']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "code"))
    )

    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Password Protected"
    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Password Protected Content"


def test_flow_with_incorrect_password(driver):
    driver.get(BASE + "/")
    clip_name = driver.find_element(By.NAME, "clip_name")
    clip_name.send_keys("Password Protected")
    clip_text = driver.find_element(By.NAME, "clip_text")
    clip_text.send_keys("Password Protected Content for Incorrec")
    clip_passwd = driver.find_element(By.NAME, "clip_passwd")
    clip_passwd.send_keys("password")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "input"))
    )
    
    clip_view_passwd = driver.find_element(By.NAME, "clip_passwd")
    clip_view_passwd.send_keys("pincorrectassword")
    driver.find_element(By.XPATH, "//button[text()='Go']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "input"))
    )

    p = driver.find_element(By.TAG_NAME, "p")
    assert p.text == "Incorrect Password!"


def test_flow_empty(driver):
    driver.get(BASE + "/")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    p = driver.find_element(By.TAG_NAME, "p")
    assert p.text == "Text Field or File Cannot be Empty!"


def test_flow_user(driver):
    driver.get(BASE + "/")
    login = driver.find_element(By.LINK_TEXT, "Login").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    assert driver.current_url == BASE + "/login"

    register_link = driver.find_element(By.LINK_TEXT, "Register").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )
    
    assert driver.current_url == BASE + "/register"

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    password_confirm = driver.find_element(By.NAME, "password_confirm")
    password_confirm.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    driver.get(BASE + "/login")

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    assert driver.current_url == BASE + "/"

    username_menu_name = driver.find_element(By.XPATH, "//button[normalize-space()='user']")

    assert driver.find_element(By.NAME, "clip_edit")


def test_flow_complete_edited(driver):
    driver.get(BASE + "/")
    login = driver.find_element(By.LINK_TEXT, "Login").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    assert driver.current_url == BASE + "/login"

    register_link = driver.find_element(By.LINK_TEXT, "Register").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )
    
    assert driver.current_url == BASE + "/register"

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    password_confirm = driver.find_element(By.NAME, "password_confirm")
    password_confirm.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    driver.get(BASE + "/login")

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    assert driver.find_element(By.XPATH, "//button[normalize-space()='user']")

    assert driver.current_url == BASE + "/"

    clip_name = driver.find_element(By.NAME, "clip_name")
    clip_name.send_keys("Test Name edited")
    clip_text = driver.find_element(By.NAME, "clip_text")
    clip_text.send_keys("Sample Text for test")
    driver.find_element(By.CSS_SELECTOR, "label[for='clip_edit']").click()
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "clip_text"))
    )

    clip_text_updated = driver.find_element(By.ID, "clip_text")
    clip_text_updated.clear()
    clip_text_updated.send_keys("This text was updated.")
    driver.find_element(By.XPATH, "//button[normalize-space()='Update']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "p"))
    )

    update_confirm = driver.find_element(By.TAG_NAME, "p")
    assert update_confirm.text == "Clip has been updated"


def test_flow_dashboard(driver):
    driver.get(BASE + "/")
    login = driver.find_element(By.LINK_TEXT, "Login").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    assert driver.current_url == BASE + "/login"

    register_link = driver.find_element(By.LINK_TEXT, "Register").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )
    
    assert driver.current_url == BASE + "/register"

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    password_confirm = driver.find_element(By.NAME, "password_confirm")
    password_confirm.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Register']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h2"))
    )

    driver.get(BASE + "/login")

    username = driver.find_element(By.NAME, "username")
    username.send_keys("user")

    password = driver.find_element(By.NAME, "password")
    password.send_keys("password1")

    driver.find_element(By.XPATH, "//button[normalize-space()='Login']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    assert driver.current_url == BASE + "/"

    clip_name = driver.find_element(By.NAME, "clip_name")
    clip_name.send_keys("Dash Test")
    clip_text = driver.find_element(By.NAME, "clip_text")
    clip_text.send_keys("Sample Text for Dash test")
    driver.find_element(By.XPATH, "//button[text()='Save']").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    driver.find_element(By.XPATH, "//button[normalize-space()='user']").click()
    driver.find_element(By.LINK_TEXT, "Dashboard").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "table"))
    )

    assert driver.current_url == BASE + "/dashboard"

    verify_name_in_table = driver.find_element(By.TAG_NAME, "td")
    assert verify_name_in_table.text == "Dash Test"
    
    driver.find_element(By.LINK_TEXT, "Go").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "code"))
    )
    
    h1 = driver.find_element(By.TAG_NAME, "h1")
    assert h1.text == "Dash Test"

    code = driver.find_element(By.TAG_NAME, "code")
    assert code.text == "Sample Text for Dash test"

    driver.get(BASE + "/dashboard")
    driver.find_element(By.LINK_TEXT, "Delete").click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "h1"))
    )

    assert driver.find_element(By.LINK_TEXT, "Start Creating?")
