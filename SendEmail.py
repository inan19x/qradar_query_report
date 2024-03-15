#!/usr/bin/env python3
import sys
import os
import pyodbc
import smtplib
import ssl
import json
import email
import email.header
import email.mime.multipart
import locale

from datetime import datetime, timedelta
from xml.dom import minidom
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from arielapiclient import APIClient

sys.path.append(os.path.realpath('modules'))


class SendCyberAttackReport:

	def __init__(self, start_time, current_time, email_address=None):
		self.start_time = start_time
		self.current_time = current_time

		if email_address is None:
		    self.email_address = None
		else:
		    self.email_address = email_address

	def run(self):

		# Creates instance of APIClient. It contains all of the API methods.
		api_client = APIClient()

		connection = self.get_mssql_connection('Dashboard')

		current_time = self.current_time
		start_time = self.start_time

		print('Pulling data for period: ' + start_time + ' - ' + current_time)

		locale.setlocale(locale.LC_TIME, 'id_ID.UTF-8')
		
		report_date = datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S")

		date_ 	= '{0}'.format(report_date.strftime("%d %B %Y"))

		table_metadata = {}
		table_metadata['table_name'] = '[Dashboard].[dbo].[cyberattack_daily_new_3]'
		table_metadata['date'] = start_time

		time_period = {}
		time_period['start_time'] = start_time
		time_period['end_time'] = current_time
		
		# get grouped data for today
		today_data				= self.get_cyberattack_summary_grouped_by_attackclassif(connection, table_metadata)

		# get grouped data for yesterday
		yesterday_date 			= datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S") - timedelta(1)
		table_metadata['date'] 	= '{0}'.format(yesterday_date.strftime("%Y-%m-%d %H:%M:%S")) 
		yesterday_data 			= self.get_cyberattack_summary_grouped_by_attackclassif(connection, table_metadata)

		# initialization
		total_events = 0
		total_cyberattack = 0
		external_hacking = 0
		internal_hacking = 0
		yesterday_external_hacking = 0
		yesterday_internal_hacking = 0

		external_data = {}
		internal_data = {}
		yesterday_external_data = {}
		yesterday_internal_data = {}

		# processing today data
		for row in today_data:
			if 'External' in row[1]:
				external_hacking += row[2]

				if row[0] not in external_data:
					external_data[row[0]] = row[2]
				else:
					external_data[row[0]] += row[2]
			else:
				internal_hacking += row[2]

				if row[0] not in internal_data:
					internal_data[row[0]] = row[2]
				else:
					internal_data[row[0]] += row[2]

			total_cyberattack += row[2]

		# processing yesterday data
		for row in yesterday_data:
			if 'External' in row[1]:
				yesterday_external_hacking += row[2]

				if row[0] not in yesterday_external_data:
					yesterday_external_data[row[0]] = row[2]
				else:
					yesterday_external_data[row[0]] += row[2]
			else:
				yesterday_internal_hacking += row[2]

				if row[0] not in yesterday_internal_data:
					yesterday_internal_data[row[0]] = row[2]
				else:
					yesterday_internal_data[row[0]] += row[2]

		external_threat_key = list(external_data.keys())
		internal_threat_key = list(internal_data.keys())

		# Get Total Event
		table_metadata['table_name'] = '[Dashboard].[dbo].[event_daily]'
		table_metadata['date'] = start_time

		data = self.get_total_events(connection, table_metadata)
		
		for row in data:
			total_events += row[0]

		print('Total Cyber Attack ' + str(total_cyberattack))
		print('Total External Threat ' + str(external_hacking))
		print('Total Internal Threat ' + str(internal_hacking))
		print("Total Event: " + str(total_events))

		data = {}
		data['data_date'] 							= date_
		data['to']									= self.email_address
		data['total_events'] 						= '{:,}'.format(int(total_events))
		data['total_cyberattack']					= '{:,}'.format(int(total_cyberattack))
		data['total_cyberattack_percent']			= '{0:.2f}%'.format(total_cyberattack / total_events * 100)
		data['external_hacking']					= '{:,}'.format(int(external_hacking))
		data['external_hacking_percent']			= '{}%'.format((round(external_hacking / total_cyberattack * 100)))
		data['internal_hacking']					= '{:,}'.format(int(internal_hacking))
		data['internal_hacking_percent']			= '{}%'.format((round(internal_hacking / total_cyberattack * 100)))

		data['external_data'] = self.get_wording(external_threat_key, external_data, yesterday_external_data)
		data['internal_data'] = self.get_wording(internal_threat_key, internal_data, yesterday_internal_data)

		self.process_email(data)

	def get_wording(self, key_list, data, prev_day_data):
		wording = ''

		for key in key_list:
			percentage_str = ''

			if key not in prev_day_data:
				percentage_str = 'yesterday data was zero'
				wording += '<li>' + key + ': {:,} '.format(int(data[key])) + '(' + percentage_str + ')' +  '</li>'
			elif int(prev_day_data[key]) == 0:
				percentage_str = 'yesterday data was zero'
				wording += '<li>' + key + ': {:,} '.format(int(data[key])) + '(' + percentage_str + ')' +  '</li>'
			else:
				diff = (data[key] - prev_day_data[key])
				percentage = (abs(diff) / prev_day_data[key]) * 100
				percentage_str = '{0:.2f}%'.format(percentage) 

				state = 'increased' if diff > 0 else 'decreased'

				wording += '<li>' + key + ': {:,} '.format(int(data[key])) + '(' + state + ' ' + percentage_str + ' from prev day' + ')' +  '</li>'

		return wording

	def json2array(self, json_data):
		keylist = []

		if json_data:
			array_data = []

			# print(json_data)
			for key in json_data[0]:
				keylist.append(key)

			for record in json_data:
				current_record = []
				for key in keylist:
					current_record.append(str(record[key]).rstrip("\n\r"))

				array_data.append(current_record)

			return array_data

		else:
			return []

	def get_cyberattack_summary(self, connection, table_metadata):
		cursor = connection.cursor()

		query_expression = """
			SELECT  * 
			FROM {0}
			WHERE CONVERT(varchar, [Data Date], 23) = '{1}'
			""".format(table_metadata['table_name'], table_metadata['date'])

		cursor.execute(query_expression)

		rows = cursor.fetchall()

		return rows

	def get_cyberattack_summary_grouped_by_attackclassif(self, connection, table_metadata):
		cursor = connection.cursor()

		query_expression = """
			SELECT  [Attack Classification], [Threat Source], SUM([Total Event]) AS 'Total'
			FROM {0}
			WHERE CONVERT(varchar, [Data Date], 23) = '{1}'
			GROUP BY [Attack Classification], [Threat Source]
			ORDER BY [Attack Classification] ASC
			""".format(table_metadata['table_name'], table_metadata['date'])

		cursor.execute(query_expression)

		rows = cursor.fetchall()

		return rows

	def get_total_events(self, connection, table_metadata):
		cursor = connection.cursor()

		query_expression = """
			SELECT  [Total Event]
			FROM {0}
			WHERE CONVERT(varchar, [Data Date], 23) = '{1}'
			""".format(table_metadata['table_name'], table_metadata['date'])

		cursor.execute(query_expression)

		rows = cursor.fetchall()

		return rows


	def process_email(self, data):
		folder_path = os.path.realpath('MailTemplate')
		
		# change this to a suitable file
		mail_content = 'Cyberattack_summary_v4.xml'
		# mail_content = 'dummy.xml'
			
		mail_template = 'mail_template.html'

		xmldoc = minidom.parse(os.path.join(folder_path, mail_content))

		to_addresses 	= []
		cc_addresses 	= []
		texts 			= []

		to_content = xmldoc.getElementsByTagName('to')
		for to in to_content:
			to_addresses.append(to.firstChild.data.strip())

		cc_content = xmldoc.getElementsByTagName('cc')
		for cc in cc_content:
			cc_addresses.append(cc.firstChild.data.strip())

		text_content = xmldoc.getElementsByTagName('text')
		for text in text_content:
			texts.append(text.firstChild.wholeText)

		if data['to'] is None:
		    content_data	    = {'to': to_addresses, 'cc': cc_addresses, 'text': texts}
		    receiver_email 		= content_data['to']
		    cc_email 			= content_data['cc']
		    to_addresses		= receiver_email + cc_email
		
		else:
		    content_data	    = {'to': data['to'].strip(), 'text': texts}
		    receiver_email 		= content_data['to']
		    to_addresses		= receiver_email

		text    = ''.join(content_data['text'])

		text = text.replace('tanggalnya', data['data_date'])
		text = text.replace('total_cyberattack_percent', data['total_cyberattack_percent'])
		text = text.replace('external_hacking_percent', data['external_hacking_percent'])
		text = text.replace('internal_hacking_percent', data['internal_hacking_percent'])
		text = text.replace('total_events', data['total_events'])
		text = text.replace('total_cyberattack', data['total_cyberattack'])
		text = text.replace('external_hacking', data['external_hacking'])
		text = text.replace('internal_hacking', data['internal_hacking'])
		text = text.replace('external_data', data['external_data'])
		text = text.replace('internal_data', data['internal_data'])



		message.set_charset('utf-8')
		
		message['Subject'] 	= email.header.Header('[Automated Report] Cyber Attack Summary' + ' - ' + data['data_date'])
		message['From'] 	= email.header.Header(sender_email)

		if data['to'] is None:
			message['To'] 		= email.header.Header(', '.join(receiver_email).strip())
			message['Cc'] 		= email.header.Header(', '.join(cc_email).strip())
		else:
			message['To'] 		= email.header.Header(receiver_email.strip())
			
		
		message['Message-ID'] = email.header.Header(email.utils.make_msgid())
		message['Date']		= email.header.Header(email.utils.formatdate())

		# Create a secure SSL context
		context = ssl.create_default_context()

		file = os.path.join(folder_path, mail_template)

		reader = open(file, 'r')
		mail_template_content = reader.read()

		css_style = """
			body {
				font-family: calibri, arial;
			}
			table, th, td {
				border: 1px solid black;
				border-collapse: collapse;
				font-size: 12pt;
			}
			th {
				background-color: black;
				color: #ffffff;
				text-align: left;
			}
			h2 {
				font-size: 18pt;
			}
			h3 {
				font-size: 14pt;
			}
			p { 
				margin: 1px;
				font-size: 12pt;
			}
			"""

		data = mail_template_content.format(css_style, text)

		mail = MIMEText(data, 'html')
		
		message.attach(mail)

		log_files = []

		log_path = os.path.realpath('user_log')

		for r, d, f in os.walk(log_path):
			for file in f:
				if 'Detail.xlsx' in file:
					log_files.append(file)

		for log in log_files:
			attachment = open(os.path.join(log_path, log), 'rb')

			try:
				payload = MIMEBase('application', 'octet-stream')
				payload.set_payload(attachment.read())
				encoders.encode_base64(payload)
				payload.add_header(
					'Content-Disposition',
					'attachment; filename= {}'.format(log)
				)
				message.attach(payload)
			finally:
				print('Adding attachment files done')
				attachment.close()
				os.remove(os.path.join(log_path, log))

		# Try to log in to server and send email
		server = smtplib.SMTP(smtp_server,port)
		server.starttls() # Secure the connection
		server.login(username, password)

		# TODO: Send email here
		server.sendmail(sender_email, to_addresses, message.as_string())
		server.quit()
		

	def get_mssql_connection(self, dbname):
		connection = pyodbc.connect('driver={ODBC Driver 17 for SQL Server};server=RVSIEMW1ABC19WP;database=' + dbname + ';uid=subes;pwd=Tableau@2020;ColumnEncryption=Enabled;')
		return connection
