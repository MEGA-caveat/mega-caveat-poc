# automated login via selenium
# relevant parts from previous PoC code

import multiprocessing

from selenium import webdriver, common

# local webclient login page
URL = "http://webclient.local/login"

# test account login details, must be filled in first
UNAME = ""
PW = ""

# mega website
MEGA_UNAME_FIELD_ID = "login-name2"
MEGA_PW_FIELD_ID = "login-password2"
MEGA_LOGIN_FORM_ID = "login_form"
MEGA_LOGIN_FORM_BUTTON_CLASS = "login-button"


class Victim:

    def __init__(self):
        pass

    def run(self, queue):
        # set up driver

        firefox_caps = webdriver.DesiredCapabilities.FIREFOX 
        firefox_caps["marionette"] = True
        firefox_caps["proxy"] = {
            "proxyType": "MANUAL",
            "httpProxy": "localhost:8080",
            "sslProxy": "localhost:8080"
        }
        self.driver = webdriver.Firefox()  #capabilities=firefox_caps

        self.driver.get(URL)
        webdriver.support.wait.WebDriverWait(self.driver, timeout=5).until(lambda d: d.find_element_by_id(MEGA_UNAME_FIELD_ID))

        # login

        uname_field = self.driver.find_element_by_id(MEGA_UNAME_FIELD_ID)
        uname_field.send_keys(UNAME)

        pw_field = self.driver.find_element_by_id(MEGA_PW_FIELD_ID)
        pw_field.send_keys(PW)

        login_form = self.driver.find_element_by_id(MEGA_LOGIN_FORM_ID)
        login_button = login_form.find_element(by=webdriver.common.by.By.CLASS_NAME, value=MEGA_LOGIN_FORM_BUTTON_CLASS)
        login_button.click()

        while queue.empty():
            pass

        signal = queue.get()
        if signal == "close":
            print("Closing victim session...")
            self.driver.close()
            self.driver.quit()


if __name__ == "__main__":

    victim = Victim()
    fake_queue = multiprocessing.Queue()
    victim.run(fake_queue)

    while True:
        pass