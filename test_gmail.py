import smtplib

EMAIL = "omanrynee@gmail.com"
APP_PASSWORD = "xcdp stmm muqv zwcg"

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL, APP_PASSWORD)
    print("Login Successful!")
    server.quit()
except Exception as e:
    print("Error:", e)