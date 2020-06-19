# -*- coding: utf-8 -*-
from queue import Queue
from threading import Thread

import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr

from utils import get_time_str
import json


class EmailQueue(object):
    def __init__(self, smtp_server=None, smtp_port=465, from_addr=None, smtp_pass=None, from_name=None, subject="Zorg Alert", reply_to=None):

        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.password = smtp_pass
        self.from_name = from_name
        self.subject = subject
        self.reply_to = reply_to
        
        self.msg_queue = Queue()
        self.do()

    @staticmethod
    def _format_addr(s):
        name, addr = parseaddr(s)
        return formataddr((Header(name, 'utf-8').encode(), addr))

    def put(self, to, msg):
        json_data = {}
        json_data["to"] = to
        json_data["msg"] = str(msg)
        print(json_data)
        self.msg_queue.put(json_data)

    def send(self):
        while True:
            jsondata = self.msg_queue.get()
            msg = jsondata['msg']
            to_addr = jsondata['to']
            time_str = get_time_str()
            print('[send email]', time_str, msg)
            body = f"<html><body>{msg}</body></html>"
            # -------------------------------------------------------------------------------------------------
            msg = MIMEText(body, 'html', 'utf-8')
            msg['From'] = self._format_addr("{name} {address}".format(name=self.from_name, address=self.from_addr))
            msg['To'] = ','.join(to_addr)
            msg['Subject'] = Header(self.subject, 'utf-8').encode()
            msg.add_header('reply-to', self.reply_to)
            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            server.set_debuglevel(1)
            server.login(self.from_addr, self.password)
            server.sendmail(self.from_addr, to_addr, msg.as_string())
            server.quit()

    def do(self):
        t = Thread(target=self.send)

        t.daemon = True
        t.start()


if __name__ == '__main__':
    import time
    eq = EmailQueue()
    eq.put(to="admin@email.com", msg='Starting')
    time.sleep(10)