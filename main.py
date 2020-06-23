from flask import Flask, render_template,request,redirect,url_for # For flask implementation
from bson import ObjectId # For ObjectId to work
from pymongo import MongoClient
import os
import zerto
import configparser
import bcrypt
import logging    
import base64
import json
import requests
from datetime import datetime, tzinfo, timezone, timedelta
from email_queue import EmailQueue
import time
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

requests.packages.urllib3.disable_warnings()

logFormatter = '%(asctime)s - %(levelname)s - %(message)s'
configini = configparser.ConfigParser()
configini.read('config.ini')
mongocfg = configini['mongodb']

get_zvm_interval = int(configini['job_intervals']['get_zvm'])
get_zorg_interval = int(configini['job_intervals']['get_zorg'])
get_alerts_interval = int(configini['job_intervals']['get_alerts'])

logFormatter = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(format=logFormatter, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.info("Applicaiton Starting")
scheduler = BackgroundScheduler(daemon=True)
atexit.register(lambda: scheduler.shutdown(wait=False))
scheduler.start()
app = Flask(__name__)

title = "ZORG Alert System"
heading = "ZORG Alert System"

client = MongoClient('mongodb://' + mongocfg['host'] + ':' + mongocfg['port']) #host uri
db = client.zorgalerts #Select the database
alertdb = db.alerts
zorgdb = db.zorgs
zvmdb = db.zvms
configdb = db.config


def redirect_url():
    return request.args.get('next') or \
        request.referrer or \
        url_for('index')


@app.route("/")
@app.route("/zorgs")
@app.route("/list")
def zorgs ():
    logger.debug("list zorgs api invoked")
    #Display the Uncompleted Tasks
    todos_l = zorgdb.find()
    a2="active"
    return render_template('index.html',a2=a2,todos=todos_l,t=title,h=heading)


@app.route("/zvms")
def zvms ():
    #Display the ZVM config
    logger.debug("list zvms api invoked")
    todos_l = zvmdb.find()
    a1="active"
    return render_template('zvm.html',a1=a1,todos=todos_l,t=title,h=heading)


@app.route("/config")
def config ():
    #Display the ZVM config
    logger.debug("list zcm api invoked")
    todos_l = configdb.find({"type": "zcm"})
    smtps_l = configdb.find({"type": "smtp"})
    a4="active"
    return render_template('config.html',a4=a4,todos=todos_l,smtps=smtps_l,t=title,h=heading)


@app.route("/alerts")
def alerts ():
    logger.debug("list zorgs api invoked")
    #Display the Uncompleted Tasks
    filter={
        'archived': False,
    }
    sort=list({
        'turned_on': -1
    }.items())
    todos_l = alertdb.find(filter=filter, sort=sort)
    a3="active"
    return render_template('alerts.html',a3=a3,todos=todos_l,t=title,h=heading)


@app.route("/mute")
def mute ():
#    #Done-or-not ICON
    id=request.values.get("_id")
    task=alertdb.find({"_id":ObjectId(id)})
    if(task[0]["muted"]=="True"):
        alertdb.update({"_id":ObjectId(id)}, {"$set": {"muted":"False"}})
    else:
        alertdb.update({"_id":ObjectId(id)}, {"$set": {"muted":"True"}})   
    return redirect("/alerts")

@app.route("/disable")
def disable():
#    #Done-or-not ICON
    id=request.values.get("_id")
    zorg=zorgdb.find({"_id":ObjectId(id)})
    if(zorg[0]["email_enabled"]=="True"):
        zorgdb.update({"_id":ObjectId(id)}, {"$set": {"email_enabled":"False"}})
    else:
        zorgdb.update({"_id":ObjectId(id)}, {"$set": {"email_enabled":"True"}})   
    return redirect("/zorgs")


@app.route("/action", methods=['POST'])
def action ():
    #Adding a Task
    logger.debug("manually add zorg api invoked")
    name=request.values.get("name")
    zorgid=request.values.get("zorgid")
    email=request.values.get("email")
    zorgdb.insert({ "name":name, "zorgid":zorgid, "email":email, 'email_enabled': True })
    return redirect("/list")

@app.route("/zcmadd", methods=['POST'])
def zcmadd ():
    #Adding a Task
    logger.debug("add zcm api invoked")
    hostname=request.values.get("hostname")
    port=request.values.get("port")
    username=request.values.get("username")
    password=request.values.get("password")
    configdb.insert({ "type": "zcm", "hostname": hostname, "port": port, "username": username, "password": password })
    importzvms()
    importzorg()
    return redirect("/config")

@app.route("/smtpadd", methods=['POST'])
def smtpadd ():
    #Adding smtp
    logger.debug("add smtp api invoked")
    hostname=request.values.get("hostname")
    username=request.values.get("username")
    password=request.values.get("password")
    fromname=request.values.get("fromname")
    replyto=request.values.get("replyto")
    subject=request.values.get("subject")
    port=request.values.get("port")
    install_email=request.values.get("install_email")
    configdb.insert({ "type": "smtp", "hostname": hostname, "port": port, "username": username, "password": password, "fromname": fromname, "replyto": replyto, "subject": subject })
    if install_email == str(True):
        logger.info("Sending Installation Email")
        send_install_email()
    else:
        logger.info("Not sending installation Email")

    return redirect("/config")

def send_install_email():
    now = datetime.now()
    smtpconfig = configdb.find_one({"type": "smtp"})
    mail = EmailQueue(smtp_server=smtpconfig['hostname'], smtp_port=int(smtpconfig['port']), from_addr=smtpconfig['username'], smtp_pass=smtpconfig['password'], from_name=smtpconfig['fromname'], subject="New Zorg Alert System Installation", reply_to=smtpconfig['replyto'])

    to = "justin@jpaul.me"
    msg = "A new installation of the Zorg Alert System is completed."
    mail.put(to=[to], msg=msg)

@app.route("/remove")
def remove ():
    #Deleting a Task with various references
    logger.debug("delete zorg api invoked")
    key=request.values.get("_id")
    zorgdb.remove({"_id":ObjectId(key)})
    return redirect("/")


@app.route("/update")
def update ():
    logger.debug("update zorg api invoked - edit")
    id=request.values.get("_id")
    task=zorgdb.find({"_id":ObjectId(id)})
    return render_template('update.html',tasks=task,h=heading,t=title)

@app.route("/zcmupdate")
def zcmupdate ():
    logger.debug("update zcm api invoked - edit")
    id=request.values.get("_id")
    task=configdb.find({"_id":ObjectId(id)})
    return render_template('zcmupdate.html',tasks=task,h=heading,t=title)

@app.route("/smtpupdate")
def smtpupdate ():
    logger.debug("update zcm api invoked - edit")
    id=request.values.get("_id")
    task=configdb.find({"_id":ObjectId(id)})
    return render_template('smtpupdate.html',tasks=task,h=heading,t=title)


@app.route("/action3", methods=['POST'])
def action3 ():
    #Updating a Task with various references
    logger.debug("update zorg api invoked - commit")
    name=request.values.get("name")
    id=request.values.get("id")
    email=request.values.get("email")
    id=request.values.get("_id")
    zorgdb.update({"_id":ObjectId(id)}, {'$set':{ "name":name, "id":id, "email":email, 'email_enabled': True }})
    return redirect("/")

@app.route("/action4", methods=['POST'])
def action4 ():
    #Updating a zcm
    logger.debug("update zcm api invoked - commit")
    hostname=request.values.get("hostname")
    username=request.values.get("username")
    password=request.values.get("password")
    port=request.values.get("port")
    id=request.values.get("_id")
    configdb.update({"_id":ObjectId(id)}, {'$set':{ "hostname": hostname, "port": port, "username": username, "password": password }})
    importzvms()
    importzorg()
    return redirect("/config")

@app.route("/action5", methods=['POST'])
def action5 ():
    #Updating smtp
    logger.debug("update smtp api invoked - commit")
    hostname=request.values.get("hostname")
    username=request.values.get("username")
    password=request.values.get("password")
    fromname=request.values.get("fromname")
    replyto=request.values.get("replyto")
    subject=request.values.get("subject")
    port=request.values.get("port")
    id=request.values.get("_id")
    configdb.update({"_id":ObjectId(id)}, {'$set':{ "hostname": hostname, "port": port, "username": username, "password": password, "fromname": fromname, "replyto": replyto, "subject": subject }})
    return redirect("/config")

@app.route("/archivealert")
def archive ():
    logger.debug("archive alert api invoked - commit")
    id=request.values.get("_id")
    alertdb.update({"_id":ObjectId(id)}, {'$set':{ "archived":True }})
    return redirect("/alerts")


@app.route("/search", methods=['GET'])
def search():
    #Searching a Task with various references
    logger.debug("search  zorg api invoked")
    key=request.values.get("key")
    refer=request.values.get("refer")
    if(key == "_id"):
        todos_l = zorgdb.find({refer:ObjectId(key)})
    else:
        todos_l = zorgdb.find({refer:key})
    return render_template('searchlist.html',todos=todos_l,t=title,h=heading)


@app.route("/searchalerts", methods=['GET'])
def searchalerts():
    #Searching a Task with various references
    logger.debug("search alerts api invoked")
    key=request.values.get("key")
    refer=request.values.get("refer")
    if key == "":
        logger.debug("Using Wildcard Search")
        key = "*"
    todos_l = alertdb.find({refer:key})
    return render_template('alerts.html',todos=todos_l,t=title,h=heading)


@app.route("/importzvm")
@scheduler.scheduled_job('interval', id='get_zvms', minutes=get_zvm_interval, max_instances=1)
def importzvms ():
    #Import list of ZVM Servers from ZCM
    logger.debug('import ZVMs from ZCM API invoked')
    zcmconfig = configdb.find_one({"type": "zcm"})
    credentials = base64.b64encode('{}:{}'.format(zcmconfig['username'], zcmconfig['password']).encode())
    headers = {
        'Authorization': 'Basic {}'.format(credentials.decode())
    }
    headers['content-type'] = 'application/json'
    headers['Accept'] = 'application/json'
    session = None
    base = 'https://' + zcmconfig['hostname'] + ':' + zcmconfig['port']

    url = base + '/v1/session/add'

    req = requests.post(
        url,
        headers=headers,
        verify=False
    )
    if req.status_code == requests.codes.ok:
        session = req.headers.get('x-zerto-session')
        logger.debug('Login to ZCM Successful')

    if not session:
        logger.critical('ZCM - Invalid user name and/or password')
    headers['x-zerto-session'] = session

    url = base + '/v1/sites'
    zvms = requests.get(
        url,
        headers=headers,
        verify=False
        )
    for zvm in zvms.json():
        res = zvmdb.find({"zvmid": zvm['SiteIdentifier']})
        if  res.count() > 0:
            zid = zvmdb.find_one({"zvmid": zvm['SiteIdentifier']}).get('_id')
            zvmdb.update({"_id":ObjectId(zid)}, {'$set':{ "zvmid": zvm['SiteIdentifier'], "zvmname": zvm['SiteName'], "zvmhostname": zvm['HostName'], "zvmport": zvm['Port'], "zvmsession": zvm['ZvmGui']['SessionIdentifier'] }})
            logger.debug("Zvm already exists in DB, Updating Info - " + zvm['SiteIdentifier'] + " - " + zvm['SiteName'])
        else:
            logger.debug("Added zvm to DB - " + zvm['SiteIdentifier'] + " - " + zvm['SiteName'])
            zvmdb.insert({ 
                "zvmid": zvm['SiteIdentifier'], 
                "zvmname": zvm['SiteName'], 
                "zvmhostname": zvm['HostName'], 
                "zvmport": zvm['Port'],
                "zvmsession": zvm['ZvmGui']['SessionIdentifier']
            })

    url = base + '/v1/session'    
    requests.delete(
        url,
        headers=headers,
        verify=False)

    return redirect("/zvms")


@app.route("/importzorg")
@scheduler.scheduled_job('interval', id='get_zorgs', minutes=get_zorg_interval, max_instances=1)
def importzorg ():
    #Import list Zorgs in ZCM
    logger.debug('import Zorgs from ZCM API invoked')
    zcmconfig = configdb.find_one({"type": "zcm"})
    credentials = base64.b64encode('{}:{}'.format(zcmconfig['username'], zcmconfig['password']).encode())
    headers = {
        'Authorization': 'Basic {}'.format(credentials.decode())
    }
    headers['content-type'] = 'application/json'
    headers['Accept'] = 'application/json'
    session = None
    base = 'https://' + zcmconfig['hostname'] + ':' + zcmconfig['port']
    
    url = base + '/v1/session/add'

    req = requests.post(
        url,
        headers=headers,
        verify=False
    )
    if req.status_code == requests.codes.ok:
        session = req.headers.get('x-zerto-session')
        logger.debug('Login to ZCM Successful')

    if not session:
        logger.critical('ZCM - Invalid user name and/or password')
    headers['x-zerto-session'] = session

    url = base + '/v1/zorgs'
    zorgs = requests.get(
        url,
        headers=headers,
        verify=False
        )

    for zorg in zorgs.json():

        if zorgdb.find({"zorgid": zorg['ZorgIdentifier']}).count() < 1:
            logger.debug("Zorg added to DB - " + zorg['ZorgIdentifier'] + " - " + zorg['Name'])
            zorgdb.insert({ "zorgid": zorg['ZorgIdentifier'], "name": zorg['Name'], 'email_enabled': False })
        else:
            logger.debug("Zorg already exists in DB - " + zorg['ZorgIdentifier'] + " - " + zorg['Name'])

    url = base + '/v1/session'    
    requests.delete(
        url,
        headers=headers,
        verify=False)

    return redirect("/")


@app.route("/importalerts)")
@scheduler.scheduled_job('interval', id='get_alerts', minutes=get_alerts_interval, max_instances=1)
def importalerts():
    zvms = zvmdb.find()
    
    for zvm in zvms:
        logger.debug("Importing Alerts from " + zvm['zvmname'] + " - " + zvm['zvmid'])
        zvmsession = zvm['zvmsession']
        url = 'https://' + zvm['zvmhostname'] + ':' + str(zvm['zvmport']) + "/"
        zapi = zerto.Zerto(url, session=zvmsession)

        alerts = zapi.get_alert()
        if  len(alerts) > 0:
            logger.debug("Checking " + str(len(alerts)) + " alerts for " + zvm['zvmname'] + " - " + zvm['zvmid'])
            for alert in alerts:
                alertinfo = {
                    "vpgs": alert.vpgs,
                    "zorgs": alert.zorgs,
                    "help_identifier": alert.help_identifier,
                    "site_identifier": alert.site_identifier,
                    "alert_identifier": alert.alert_identifier,
                    "turned_on": alert.turned_on,
                    "description": alert.description,
                    "entity": alert.entity,
                    "level": alert.level,
                    "is_dismissed": alert.is_dismissed,
                    "email_sent": False,
                    "muted": False,
                    "archived": False
                }
                result = alertdb.find({ "site_identifier": alert.site_identifier, "turned_on": alert.turned_on, "description": alert.description, "alert_identifier": alert.alert_identifier })
                if  result.count() == 0:
                    logger.debug("Alert added to DB - " + alert.alert_identifier + " " + alert.site_identifier + " - " + alert.description)
                    alertdb.insert(alertinfo)
                else:
                    id = None
                    for record in result:
                        id = record['_id']
                    logger.debug("Alert already exists in DB - " + alert.site_identifier + " - " + alert.description + " - " + str(id))
                    alertdb.update({"_id":id}, {"$set": {"is_dismissed": alert.is_dismissed}})
                    
        else:
            logger.debug("No Alerts Present on - " + zvm['SiteIdentifier'] + " - " + zvm['SiteName'])

    return ("No Alert Logic")


@app.route("/sendemail")
@scheduler.scheduled_job('interval', id='send_emails', minutes=get_alerts_interval, max_instances=1)
def send_email():
    count = 0
    total = 0
    now = datetime.now()
    earlier = now - timedelta(hours=24)
    filter={
        'turned_on': {
            '$gt': datetime(earlier.year, earlier.month, earlier.day, earlier.hour, earlier.minute, earlier.second, tzinfo=timezone.utc)
        },
        "email_sent": False, 
        "muted": False,
        "archived": False,
        "is_dismissed": False
    }
    result = alertdb.find(filter=filter) 
    if  result.count() == 0:
        logger.debug("No Emails to send")
        return ("No Emails to send")
    else:
        smtpconfig = configdb.find_one({"type": "smtp"})
        print(smtpconfig['hostname'])
        print(smtpconfig['port'])
        print(smtpconfig['username'])
        print(smtpconfig['fromname'])
        print(smtpconfig['replyto'])
        print(smtpconfig['subject'])

        mail = EmailQueue(smtp_server=smtpconfig['hostname'], smtp_port=int(smtpconfig['port']), from_addr=smtpconfig['username'], smtp_pass=smtpconfig['password'], from_name=smtpconfig['fromname'], subject=smtpconfig['subject'], reply_to=smtpconfig['replyto'])

        for record in result:
            total += 1
            zorgs = record['zorgs']
            if len(zorgs) > 0:
                for zorg in zorgs:
                    count += 1
                    zorginfo = zorgdb.find_one({"zorgid":zorg})
                    zorgemail = zorginfo['email']
                    zorgname = zorginfo['name']
                    email_enabled = zorginfo['email_enabled']
                    if email_enabled == "True":
                        logger.debug("Sending Email to " + str(zorgname) + " - " + str(zorgemail) + " - Alert: " + str(record['description']))
                        msg = "<b>A Zerto Alert has occurred:<br><h2>" + record['help_identifier'] + " - " + record['level'] + "</h2> - <p>" + record['description']
                        mail.put([zorgemail], msg)
                    else:
                        logger.debug("Email is disabled for " + str(zorgname) + " - " + str(zorgemail) + " - Alert: " + str(record['description']))
            alertdb.update({"_id":record['_id']}, {"$set": {"email_sent": True}})
    logger.debug("Processed " + str(total) + " alerts, and sent " + str(count) + " emails.")
    return(str(count) + " Emails Sent")

@app.route("/cronjobs")
def cronjobs ():
    importzvms()
    importzorg()
    importalerts()
    send_email()
    return ("CronJobs Executed")

def print_date_time():
    print(time.strftime("%A, %d. %B %Y %I:%M:%S %p"))

if __name__ == "__main__":
    app.run(host='0.0.0.0')

