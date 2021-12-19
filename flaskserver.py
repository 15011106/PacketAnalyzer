# -- coding: utf-8 --
#!flask/bin/python
import sys
import os
import time
import numpy as numpy
from matplotlib import pyplot as plt
from matplotlib import dates
#from analysismodule import *
from flask import Flask, send_from_directory, render_template, request, redirect, Response, url_for, send_file
from werkzeug import secure_filename, SharedDataMiddleware
from analysismodule import processByFilter, pcapSqlite

UPLOAD_FOLDER='./result/pcap'
ALLOWED_EXTENSIONS = set(['pcap', 'pcapng'])

filterOption = {
	"do_isp":"yes",
	"start_time":None,
	"end_time":None,
	"UDP":None,
	"TCP":None,
	"ICMP":None,
	"others":None,
	"SIP":None,
	"DIP":None,
	"SPORT":None,
	"DPORT":None,
	"SMAC":None,
	"DMAC":None
}
app = Flask(__name__)
app.config['resultdata'] = UPLOAD_FOLDER
app.config['filter_option'] = filterOption


### Result export function

def clear_filter():
	global filterOption
	filterOption = {
		"do_isp":"Yes",
		"start_time":None,
		"end_time":None,
		"UDP":None,
		"TCP":None,
		"ICMP":None,
		"others":None,
		"SIP":None,
		"DIP":None,
		"SPORT":None,
		"DPORT":None,
		"SMAC":None,
		"DMAC":None
	}

def make_graph():
	pass

def draw_world_bap():
	pass

def detect_arp():
	pass

def tcp_tracer():
	pass



### Main page ###
@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
	# serve index template
	caseList = os.listdir("./result/DB")
	caseList = [case.replace('.db','') for case in caseList]
	clear_filter()

	return render_template('index.html', caseList=caseList)


### Methods for pcap file submit and uploads ###
@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
	if request.method == 'POST':

		### Check for form if its empty or not ###
		if('file' not in request.files or 
			request.form['casename'] == ''):
			return redirect(url_for('index'))
		#print request.form

		### Process request form ###
			## File name ## 
		pcapfile = request.files['file']
		filename = secure_filename(pcapfile.filename)
		filepath = os.path.join(app.config['resultdata'], filename)

			## Case name and isp part ##
		reqCasename = request.form['casename']
		if('do-isp' in request.form):
			doIsp = request.form['do-isp']
			filterOption['do_isp'] = None
		else: 
			doIsp = None;

		### Save pcap file first ###
		pcapfile.save(filepath)
		pcapfile.close()
		clear_filter()
		### Analyze pcap file ###
		#scapymodule.pcapAnalysis(filepath, reqCasename, doIsp)

		### Redirect to result page ###
		return redirect(url_for('show_result_page', casename=reqCasename))
	else:
		return redirect(url_for('index'))


### Redirection for result page ###
@app.route('/result_page')
@app.route('/result_page/<casename>')
def show_result_page(casename=None):
	db_path = "./result/DB/" + str(casename)
	exported = {}
	print filterOption

	### Graph Handler and get Number Of protocol at once
	graphHandler = processByFilter.processByFilter(casename, filterOption)
	ret = graphHandler.getProcessedData(filterOption)
	exported["numberOfProtocol"] = ret['protocol_number']
	exported["numberOfIPs"] = ret['ip_number']
	exported["numberOfPorts"] = ret['port_number']
	exported['numberOfPackets'] = ret["packet_number"]
	exported['allpackets'] = ret['packets']
	exported['arp'] = ret['arp']

	#print exported['arp']
	if(ret["loc"]):
		exported["Locations"] = ret["loc"]
		exported['numberOfCountry']= ret['country_number']
		exported['numberOfISP'] = ret['ISPnumber']
	else:
		exported["Locations"] = None
		exported['numberOfCountry']= None
		exported['numberOfISP'] = None

	#print exported
	print ret['loc']

	return render_template('result.html', casename=casename, exported=exported, filter=filterOption)


@app.route('/get_filter_data/<casename>', methods = ['POST', 'GET'])
def get_filter_data(casename=None):

	if("SIP" in request.form):
		filterOption["SIP"] = request.form["SIP"]
	if("DIP" in request.form):
		filterOption["DIP"] = request.form["DIP"]

	if("SPORT" in request.form):
		filterOption["SPORT"] = request.form["SPORT"]
	if("DPORT" in request.form):
		filterOption["DIP"] = request.form["DIP"]

	if("TCP" in request.form):
		filterOption["TCP"] = request.form["TCP"]
	if("UDP" in request.form):
		filterOption["UDP"] = request.form["UDP"]
	if("ICMP" in request.form):
		filterOption["ICMP"] = request.form["ICMP"]
	if("others" in request.form):
		filterOption["others"] = request.form["others"]
	# ImmutableMultiDict([('DPORT', u''), ('SIP', u'+172.16.0.107'), ('DIP', u''), ('SPORT', u'')]) 


	return redirect("/result_page/"+ casename)

@app.route("/open_img/<casename>/<image>")
def get_img(casename, image):
	#print casename, image
	filename = "./result/" + casename + "/" + image
	return send_file(filename, mimetype='image/gif')


if __name__ == '__main__':
	# run!
	app.debug=True
	app.run(host="0.0.0.0")