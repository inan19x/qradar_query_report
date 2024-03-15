#!/usr/bin/env python3
import sys
import os
import json
import csv
import smtplib
import pyodbc
import ssl
import os
import xlwt
import xlsxwriter
import time
import datetime as dt

from calendar import monthrange
from datetime import datetime, timedelta

sys.path.append(os.path.realpath('modules'))
from arielapiclient import APIClient

class CyberAttackSummary:

	def __init__(self, start_time, current_time):
		self.start_time 	= start_time
		self.current_time 	= current_time

	def run(self):
		start_time 		= self.start_time
		current_time	= self.current_time

		connection = self.get_mssql_connection()

		# Creates instance of APIClient. It contains all of the API methods.
		api_client = APIClient()
		
		report_date		= start_time

		print('Pulling data for period: ' + start_time + ' - ' + current_time)

		time_period = {}
		time_period['start_time'] = start_time
		time_period['end_time'] = current_time
		
		# Data sources:

		raw_data_internet_firewall	= self.get_log(api_client, 'Internet Firewall', time_period)
		
		# json2array by default it removes the header
		qradar_if 					= self.json2array(raw_data_internet_firewall)

		event_detail_dict = {}
		
		event_detail_dict['cts_internet_fw'] 	= qradar_if_ip.copy()

		total_event_if				= self.compute_total(qradar_if)

		csv_data = []
		csv_data.append(['Attack Classification', 'Threat Source', 'Log Source', 'Total Event', 'Data Date'])

		csv_data.append(['External Hacking', 'External Threat', 'Internet Firewall', total_event_if, report_date])
      
		# # logging
		csv_to_xls = {}

		csv_to_xls['Summary'] 						= csv_data
		csv_to_xls['Internet Firewall']				= raw_data_internet_firewall
		
		# ---------------------------------------------------------------------------------------------------

		# record Event detail into DB

		key_list_event_detail = list(event_detail_dict.keys())
		
		for key in key_list_event_detail:
			
			data = event_detail_dict[key]

			tmp = []
			
			if len(data) == 0:
				continue

			for row in data:
				tmp.append(row)
			
			table_metadata 				= self.examine_data(tmp)
			table_metadata['name'] 		= key
			table_metadata['data date'] = time_period['start_time']

			# create and insert table
			self.create_mssql_table(connection, table_metadata)
			self.insert_mssql_table_2(connection, table_metadata)

		# ---------------------------------------------------------------------------------------------------

		# table metadata initialization
		table_metadata 				= self.examine_data(csv_data)
		table_metadata['name'] 		= 'cyberattack_daily'
		table_metadata['data date'] = time_period['start_time']

		# create and insert table
		self.create_mssql_table(connection, table_metadata)
		self.insert_mssql_table(connection, table_metadata)

		# TOTAL EVENT
		raw_data_vpn	= self.get_log(api_client, 'Total Event', time_period)
		total_event 	= self.json2array(raw_data_vpn)
		
		total_event = int(float(total_event.pop(0).pop(0)))

		header 	= ['Total Event', 'Data Date']
		content = [total_event, start_time]

		combined_data 	= [header, content]  

		if len(combined_data) > 0:
			table_metadata				= self.examine_data(combined_data)
			table_metadata['name'] 		= 'event_daily'
			table_metadata['data date'] = time_period['start_time']

			# create and insert table
			self.create_mssql_table(connection, table_metadata)
			self.insert_mssql_table(connection, table_metadata)

		self.create_xlsx(csv_to_xls, 'Detail.xlsx')

	def get_mssql_connection(self):
		connection = pyodbc.connect('driver={ODBC Driver 17 for SQL Server};server=<DBHOST>;database=<DBNAME>;uid=<DBUSER>;pwd=<DBPASSWD>;ColumnEncryption=Enabled;')
		return connection

	def lookup_the_data_type(self, table_metadata):
		info_of_max_num_char = [0]*len(table_metadata['header'])

		for data in table_metadata['data']:
			for n in range(len(data)):
				if len(str(data[n])) > info_of_max_num_char[n]:
					info_of_max_num_char[n] = len(str(data[n]))

		data_type = [None]*len(table_metadata['header'])
		for counter in range(len(table_metadata['header'])):
 
			if str(table_metadata['data'][0][counter]).isnumeric():
				data_type[counter] = 'int'
			elif not table_metadata['data'][0][counter].isnumeric() and info_of_max_num_char[counter] < 200:
    
				data_type[counter] = 'varchar(max)'
			else:
				data_type[counter] = 'varchar(max)'
		return data_type

	def examine_data(self, data, data_date=None): 
		table_metadata = {}

		is_header = True
		rows = []
		for row in data:
			if is_header:
				table_metadata['header'] = row
				is_header = False
				continue

			if data_date:
				row[-1] = data_date
			rows.append(row)

		table_metadata['data'] = rows
		table_metadata['data_type']	= self.lookup_the_data_type(table_metadata)

		return table_metadata

	def create_mssql_table(self, connection, table_metadata):
		cursor = connection.cursor()

		column_detail = []
		
		# print(table_metadata['header'])

		for n in range(len(table_metadata['header'])):
			
			column_detail.append('"' + table_metadata['header'][n] + '" ' + table_metadata['data_type'][n])

		create_table_query_expression = """
			CREATE TABLE {0}
			({1})
			""".format(table_metadata['name'], ', '.join(column_detail))

		query_expression = """
		IF (NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '{0}'))
		BEGIN
			{1}
		END
		""".format(table_metadata['name'], create_table_query_expression)
		
		cursor.setinputsizes([(pyodbc.SQL_WVARCHAR, 0, 0)])	
		
		retry_flag = True
		retry_count = 0
		cursor.execute(query_expression)
		connection.commit()

	def insert_mssql_table(self, connection, table_metadata):
		cursor = connection.cursor()

		query_expression = """
			IF (EXISTS (SELECT * FROM [Dashboard].[dbo].[{0}] WHERE CONVERT(varchar,[Data Date],23) = '{1}'))
			BEGIN
				DELETE FROM [Dashboard].[dbo].[{0}] WHERE CONVERT(varchar,[Data Date],23) = '{1}'
			END
			""".format(table_metadata['name'], table_metadata['data date'])
		
		cursor.execute(query_expression)
		connection.commit()

		cursor.fast_executemany = True  # new in pyodbc 4.0.19

		insert_query_expression = """INSERT INTO {0} ({1}) VALUES ({2})""".format(table_metadata['name'],', '.join([f'"{i}"' for i in table_metadata['header']]).replace('"None"', 'NULL'),', '.join(['?' for i in range(len(table_metadata['header']))]))

		params = table_metadata['data']

		cursor.executemany(insert_query_expression, params)
		
		connection.commit()

		print("Completed process Table {}!".format(table_metadata['name']))

	def insert_mssql_table_2(self, connection, table_metadata):
		cursor = connection.cursor()

		query_expression = """
			IF (EXISTS (SELECT * FROM [Dashboard].[dbo].[{0}] WHERE [Data Date] LIKE '{1}'))
			BEGIN
				DELETE FROM [Dashboard].[dbo].[{0}] WHERE [Data Date] LIKE '{1}'
			END
			""".format(table_metadata['name'], table_metadata['data date'])
		
		cursor.execute(query_expression)
		connection.commit()

		cursor.fast_executemany = True  # new in pyodbc 4.0.19

		insert_query_expression = """INSERT INTO {0} ({1}) VALUES ({2})""".format(table_metadata['name'],
			', '.join([f'"{i}"' for i in table_metadata['header']]).replace('"None"', 'NULL'),
			', '.join(['?' for i in range(len(table_metadata['header']))]))

		params = table_metadata['data']

		cursor.executemany(insert_query_expression, params)
		
		connection.commit()

		print("Completed process Table {}!".format(table_metadata['name']))

	def compute_total(self, data):
		total = 0

		for d in data:
			total += float(d[1])

		total = int(total)

		return total
	
	def add_array_item_in_n_position(self, the_array, n, new_item):
		new_array = []
		counter = 0

		for item in the_array:
			if counter == n:
				new_array.append(new_item)

			new_array.append(item)

			counter += 1

		return new_array
		
	def get_log(self, api_client, log_source, time_period):
		if log_source == 'Internet Firewall':
			return self.get_json_log(api_client, self.get_internet_firewall_query(time_period))
		elif log_source == 'Total Event':
			return self.get_json_log(api_client, self.get_total_event_query(time_period))

	def json2array(self, json_data, include_header=False):
		keylist = []

		
		if json_data:
			array_data = []
			
			# print(json_data)
			for key in json_data[0]:
				keylist.append(key)

			if include_header:
				array_data.append(keylist)
				# print(keylist)

			for record in json_data:
				current_record = []
				for key in keylist:
					current_record.append(str(record[key]).rstrip("\n\r"))

				array_data.append(current_record)

			return array_data

		else:
			return []

	def create_csv(self, data, path, filename):
		output_path = os.path.realpath(path)

		keylist = []

		writer = csv.writer(open(os.path.join(output_path, filename), "w", newline='', encoding="utf-8"))
		
		if data:
			for row in data:
				writer.writerow(row)

			print("Created {}".format(filename))
		else:
			print("You give nothing, we create nothing.")

	def get_json_log(self, api_client, query_expression):
		
		# Use the query parameters above to call a method. This will call
		# POST /searches on the Ariel API. (look at arielapiclient for more
		# detail).  A response object is returned. It contains
		# successful OR not successful search information.
		# The search_id corresponding to this search is contained in
		# the JSON object.
		response = api_client.create_search(query_expression)

		# Each response contains an HTTP response code.
		#  - Response codes in the 200 range indicate that your request succeeded.
		#  - Response codes in the 400 range indicate that your request failed due
		#	to incorrect input.
		#  - Response codes in the 500 range indicate that there was an error on
		#	the server side.
		#print(response.code)

		# The search is asynchronous, so the response will not be the results of
		# the search.

		# The 2 lines below parse the body of the response (a JSON object)
		# into a dictionary, so we can discern information, such AS the search_id.
		response_json = json.loads(response.read().decode('utf-8'))

		# Prints the contents of the dictionary.
		#print(response_json)

		# Retrieves the search_id of the query from the dictionary.
		search_id = response_json['search_id']

		# This block of code calls GET /searches/{search_id} on the Ariel API
		# to determine if the search is complete. This block of code will repeat
		# until the status of the search is 'COMPLETE' OR there is an error.
		response = api_client.get_search(search_id)
		error = False
		while (response_json['status'] != 'COMPLETED') and not error:
			if (response_json['status'] == 'EXECUTE') | \
					(response_json['status'] == 'SORTING') | \
					(response_json['status'] == 'WAIT'):
				response = api_client.get_search(search_id)
				response_json = json.loads(response.read().decode('utf-8'))
			else:
				print(response_json['status'])
				error = True

		# After the search is complete, call the GET /searches/{search_id} to
		# obtain the result of the search.
		# Depending on whether the "application/json" OR "application/csv"
		# method is given, return search results will be in JSON form OR CSV form.
		response = api_client.get_search_results(search_id, 'application/json')

		body = response.read().decode('utf-8')
		body_json = json.loads(body)
		# print(json.dumps(body_json, indent=n, separators=(',', ':')))
		
		# print(body_json)
		# data
		return body_json['events']

	def get_internet_firewall_query(self, time_period):
		query_expression = """
			SELECT
			QIDNAME(qid) as "Event Name",
			SUM(eventcount) as "Event Count",
			"PaloAlto: Category",
			"PaloAlto: Threat Severity",
			MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
			MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
			FROM events
			WHERE
				LOGSOURCEGROUPNAME(devicegrouplist) = 'Internet Firewalls'
			AND eventdirection = 'R2L'
			AND qid not in ('53506835')
			AND "PaloAlto: Category" = 'THREAT'
			AND ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%') 
            AND RULENAME(creeventlist) not like '%Filetype not NA%'
			GROUP BY "Event Name"
			ORDER BY "Event Count" DESC
			START '{0}' STOP '{1}'
			""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression
      
	def get_total_event_query(self, time_period):

		query_expression = """
		SELECT SUM(eventcount) AS "Total Event"
		FROM events
		WHERE (PROCESSORNAME(processorid) ilike '%eventprocessor104%' or PROCESSORNAME(processorid) ilike '%eventprocessor177%') AND logsourcename(logsourceid) <> 'SIM Generic Log DSM-103 :: eventprocessor'
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		# print(query_expression)
		return query_expression

	# ===============================
	def create_xlsx(self, data, filename):
		output_path		= os.path.realpath('user_log')

		workbook 			= xlsxwriter.Workbook(os.path.join(output_path, filename))
		summary 			= workbook.add_worksheet('Summary')
		internet_fw			= workbook.add_worksheet('Internet Firewall (Event)')
        
		header_text		= workbook.add_format({
			'align': 'center',
			'valign': 'vcenter',
			'font_name': 'Calibri',
			'font_size': 11,
			'border': 1,
			'bold': 1,
			'fg_color': '#7BC0FF'})

		text			= workbook.add_format({
			'font_name': 'Calibri',
			'font_size': 11,
			'num_format': '#,##0',
			'border': 1})	

		format_text = {'text': text, 'header': header_text}

		# summary
		self.write_summary(summary, data['Summary'], format_text)

		self.write_raw_data_in_sheet(internet_fw, data['Internet Firewall'], format_text)
		
		workbook.close()

	# write data into worksheet
	# data here is something like an array
	def write_summary(self, worksheet, data, format_text):
		worksheet.set_column(0, 0, 26)  # Width of column A set to 26.
		worksheet.set_column(1, 1, 14)  # Width of column B set to 14.
		worksheet.set_column(2, 2, 18)  # Width of column C set to 18.
		worksheet.set_column(3, 3, 11)  # Width of column D set to 11.
		worksheet.set_column(4, 4, 11)  # Width of column E set to 11.
		worksheet.set_column(5, 5, 11)  # ...
		worksheet.set_column(6, 6, 11)  # ...
		worksheet.set_column(7, 7, 11)  # ...
		worksheet.set_column(8, 8, 11)  # ...
		worksheet.set_column(9, 9, 11)  # ...
		worksheet.set_column(10, 10, 11)  # ...
		worksheet.set_column(11, 11, 11)  # ...
		worksheet.set_column(12, 12, 11)  # ...
		worksheet.set_column(13, 13, 18)  # ...

		row_counter	= 2
		col_counter = 0
		
		formatting = format_text['header']

		worksheet.merge_range('A1:A2', 'Attack Classification', formatting)
		worksheet.merge_range('B1:B2', 'Threat Source', formatting)
		worksheet.merge_range('C1:C2', 'Log Source', formatting)

		worksheet.merge_range('D1:E1', 'Ring 1', formatting)
		worksheet.write('D2', 'Total Events', formatting)
		worksheet.write('E2', 'Total Assets', formatting)

		worksheet.merge_range('F1:G1', 'Ring 2', formatting)
		worksheet.write('F2', 'Total Events', formatting)
		worksheet.write('G2', 'Total Assets', formatting)

		worksheet.merge_range('H1:I1', 'Ring 3', formatting)
		worksheet.write('H2', 'Total Events', formatting)
		worksheet.write('I2', 'Total Assets', formatting)

		worksheet.merge_range('J1:K1', 'Unidentified', formatting)
		worksheet.write('J2', 'Total Events', formatting)
		worksheet.write('K2', 'Total Assets', formatting)

		worksheet.merge_range('L1:M1', 'Total', formatting)
		worksheet.write('L2', 'Total Events', formatting)
		worksheet.write('M2', 'Total Assets', formatting)

		worksheet.merge_range('N1:N2', 'Data Date', formatting)

		formatting = format_text['text']

		data.pop(0)
		for row in data:
			col_counter = 0
			for cell in row:
				worksheet.write(row_counter, col_counter, cell, formatting)
				col_counter += 1		
			row_counter += 1

	def write_raw_data_in_sheet_array(self, worksheet, data, format_text):
		row_counter	= 0
		col_counter = 0

		if len(data) == 1:
			worksheet.set_column(row_counter, col_counter, 20)
			worksheet.write(row_counter, col_counter, 'No Data', format_text['header'])
		else:
			sentinel 	= 0
			for row in data:

				if sentinel == 0:
					formatting = format_text['header']
					sentinel = 1
				else:
					formatting = format_text['text']
				
				col_counter = 0
				for cell in row:
					worksheet.set_column(row_counter, col_counter, 20)
					worksheet.write(row_counter, col_counter, cell, formatting)
					col_counter += 1		
				row_counter += 1

	# write raw data into worksheet
	# raw data is something like dictionary format
	def write_raw_data_in_sheet(self, worksheet, data, format_text):
		
		keylist = []
		key_col = {}

		col_counter = 0
		row_counter = 0

		try:

			for key in data[0]:
				keylist.append(key)
				worksheet.set_column(col_counter, col_counter, 20)
				worksheet.write(row_counter, col_counter, key, format_text['header'])
				key_col[key] = col_counter
				col_counter = col_counter + 1
			
			row_counter = row_counter + 1

			for record in data:

				for key in keylist:
					worksheet.write(row_counter, key_col[key], record[key], format_text['text'])

				row_counter = row_counter + 1
		except:
			worksheet.set_column(row_counter, col_counter, 20)
			worksheet.write(row_counter, col_counter, 'No Data', format_text['header'])
