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
		
		# Internet Firewall
		# Incapsulsa 
		# WAF - SecureSphere (dismantled)
		# WAF - SecureSphere (dismantled)
		# PaloAlto-VPN (dismantled)
		# IronPort
		# DLP McAfee
		# Trendmicro AV
		# EDR Fireeye
		# Proxy
		# Server Farm 
		# Forescout
    # WAN Firewall
    # Trendmicro Deep Security
    # Extranet Firewall

		raw_data_internet_firewall	= self.get_log(api_client, 'Internet Firewall', time_period)
		raw_data_incapsula			= self.get_log(api_client, 'Incapsula', time_period)
		#raw_data_imperva 			= self.get_log(api_client, 'Imperva Action', time_period)
		#raw_data_palo_vpn 			= self.get_log(api_client, 'Palo VPN', time_period)
		raw_data_dlp 				= self.get_log(api_client, 'DLP', time_period)
		raw_data_officescan_1 		= self.get_log(api_client, 'Officescan 1', time_period)
		raw_data_officescan_2 		= self.get_log(api_client, 'Officescan 2', time_period)
		raw_data_edr 				= self.get_log(api_client, 'EDR', time_period)
		raw_data_proxy_1			= self.get_log(api_client, 'Proxy 1', time_period)
		raw_data_proxy_2			= self.get_log(api_client, 'Proxy 2', time_period)
		raw_data_farm_server_1 		= self.get_log(api_client, 'Farm Server 1', time_period)
		raw_data_farm_server_2 		= self.get_log(api_client, 'Farm Server 2', time_period)
		raw_data_forescout   		= self.get_log(api_client, 'ForeScout', time_period)
		raw_data_wanfw   		= self.get_log(api_client, 'WAN Firewall', time_period)
		raw_data_tmds   		= self.get_log(api_client, 'TMDS', time_period)
		raw_data_extfw   		= self.get_log(api_client, 'Extranet Firewall', time_period)

		raw_data_internet_firewall_ip	= self.get_log(api_client, 'Internet Firewall IP', time_period)
		raw_data_incapsula_ip			= self.get_log(api_client, 'Incapsula IP', time_period)
		#raw_data_imperva_ip				= self.get_log(api_client, 'Imperva Action IP', time_period)
		#raw_data_palo_vpn_ip 			= self.get_log(api_client, 'Palo VPN IP', time_period)
		raw_data_dlp_ip 				= self.get_log(api_client, 'DLP IP', time_period)
		raw_data_officescan_1_ip 		= self.get_log(api_client, 'Officescan 1 IP', time_period)
		raw_data_officescan_2_ip 		= self.get_log(api_client, 'Officescan 2 IP', time_period)
		raw_data_edr_ip 				= self.get_log(api_client, 'EDR IP', time_period)
		raw_data_proxy_1_ip				= self.get_log(api_client, 'Proxy 1 IP', time_period)
		raw_data_proxy_2_ip				= self.get_log(api_client, 'Proxy 2 IP', time_period)
		raw_data_farm_server_1_ip		= self.get_log(api_client, 'Farm Server 1 IP', time_period)
		raw_data_farm_server_2_ip		= self.get_log(api_client, 'Farm Server 2 IP', time_period)
		raw_data_forescout_ip  			= self.get_log(api_client, 'ForeScout IP', time_period)
		raw_data_wanfw_ip  			= self.get_log(api_client, 'WAN Firewall IP', time_period)
		raw_data_tmds_ip  			= self.get_log(api_client, 'TMDS IP', time_period)
		raw_data_extfw_ip  			= self.get_log(api_client, 'Extranet Firewall IP', time_period)
		
		# json2array by default it removes the header
		qradar_if 					= self.json2array(raw_data_internet_firewall)
		qradar_incap 				= self.json2array(raw_data_incapsula)
		#qradar_imperva		 		= self.json2array(raw_data_imperva)
		#qradar_palo 				= self.json2array(raw_data_palo_vpn)
		qradar_dlp  				= self.json2array(raw_data_dlp)
		qradar_officescan_1			= self.json2array(raw_data_officescan_1)
		qradar_officescan_2			= self.json2array(raw_data_officescan_2)
		qradar_edr 					= self.json2array(raw_data_edr)
		qradar_proxy_1 				= self.json2array(raw_data_proxy_1)
		qradar_proxy_2 				= self.json2array(raw_data_proxy_2)
		qradar_fs_1					= self.json2array(raw_data_farm_server_1)
		qradar_fs_2					= self.json2array(raw_data_farm_server_2)
		qradar_forescout			= self.json2array(raw_data_forescout)
		qradar_wanfw    			= self.json2array(raw_data_wanfw)
		qradar_tmds     			= self.json2array(raw_data_tmds)
		qradar_extfw     			= self.json2array(raw_data_extfw)

		qradar_if_ip 				= self.json2array(raw_data_internet_firewall_ip, True)
		qradar_incap_ip 			= self.json2array(raw_data_incapsula_ip, True)
		#qradar_imperva_ip	 		= self.json2array(raw_data_imperva_ip, True)
		#qradar_palo_ip 				= self.json2array(raw_data_palo_vpn_ip, True)
		qradar_dlp_ip  				= self.json2array(raw_data_dlp_ip, True)
		qradar_officescan_1_ip		= self.json2array(raw_data_officescan_1_ip, True)
		qradar_officescan_2_ip		= self.json2array(raw_data_officescan_2_ip, True)
		qradar_edr_ip				= self.json2array(raw_data_edr_ip, True)
		qradar_proxy_1_ip			= self.json2array(raw_data_proxy_1_ip, True)
		qradar_proxy_2_ip			= self.json2array(raw_data_proxy_2_ip, True)
		qradar_fs_1_ip				= self.json2array(raw_data_farm_server_1_ip, True)
		qradar_fs_2_ip				= self.json2array(raw_data_farm_server_2_ip, True)
		qradar_forescout_ip			= self.json2array(raw_data_forescout_ip, True)
		qradar_wanfw_ip 			= self.json2array(raw_data_wanfw_ip, True)
		qradar_tmds_ip  			= self.json2array(raw_data_tmds_ip, True)
		qradar_extfw_ip  			= self.json2array(raw_data_extfw_ip, True)

		event_detail_dict = {}
		
		event_detail_dict['cts_internet_fw'] 	= qradar_if_ip.copy()
		event_detail_dict['cts_incapsula'] 		= qradar_incap_ip.copy()
		#event_detail_dict['cts_imperva']		= qradar_imperva_ip.copy()
		#event_detail_dict['cts_paloalto']		= qradar_palo_ip.copy()
		event_detail_dict['cts_dlp']			= qradar_dlp_ip.copy()
		event_detail_dict['cts_tm_mc']			= qradar_officescan_1_ip.copy()
		event_detail_dict['cts_tm_iu']			= qradar_officescan_2_ip.copy()
		event_detail_dict['cts_edr']			= qradar_edr_ip.copy()
		event_detail_dict['cts_proxy_mc']		= qradar_proxy_1_ip.copy()
		event_detail_dict['cts_proxy_iu']		= qradar_proxy_2_ip.copy()
		event_detail_dict['cts_fs_mc']			= qradar_fs_1_ip.copy()
		event_detail_dict['cts_fs_ns']			= qradar_fs_2_ip.copy()
		event_detail_dict['cts_forescout']		= qradar_forescout_ip.copy()
		event_detail_dict['cts_wanfw']  		= qradar_wanfw_ip.copy()
		event_detail_dict['cts_tmds']   		= qradar_tmds_ip.copy()
		event_detail_dict['cts_extfw']   		= qradar_extfw_ip.copy()

		total_event_if				= self.compute_total(qradar_if)
		total_event_incap			= self.compute_total(qradar_incap)
		#total_event_imperva			= self.compute_total(qradar_imperva)
		#total_event_palo			= self.compute_total(qradar_palo)
		total_event_dlp				= self.compute_total(qradar_dlp)
		total_event_officescan_1	= self.compute_total(qradar_officescan_1)
		total_event_officescan_2	= self.compute_total(qradar_officescan_2)
		total_event_edr				= self.compute_total(qradar_edr)
		total_event_proxy_1			= self.compute_total(qradar_proxy_1)
		total_event_proxy_2			= self.compute_total(qradar_proxy_2)
		total_event_fs_1			= self.compute_total(qradar_fs_1)
		total_event_fs_2			= self.compute_total(qradar_fs_2)
		total_event_forescout		= self.compute_total(qradar_forescout)
		total_event_wanfw   		= self.compute_total(qradar_wanfw)
		total_event_tmds    		= self.compute_total(qradar_tmds)
		total_event_extfw    		= self.compute_total(qradar_extfw)

		ring_info_if				= self.compute_ring_info(qradar_if_ip)
		ring_info_incap				= self.compute_ring_info(qradar_incap_ip)
		#ring_info_imperva			= self.compute_ring_info(qradar_imperva_ip)
		#ring_info_palo				= self.compute_ring_info(qradar_palo_ip)
		ring_info_dlp				= self.compute_ring_info(qradar_dlp_ip)
		ring_info_officescan_1		= self.compute_ring_info(qradar_officescan_1_ip)
		ring_info_officescan_2		= self.compute_ring_info(qradar_officescan_2_ip)
		ring_info_edr				= self.compute_ring_info(qradar_edr_ip)
		ring_info_proxy_1			= self.compute_ring_info(qradar_proxy_1_ip)
		ring_info_proxy_2			= self.compute_ring_info(qradar_proxy_2_ip)
		ring_info_fs_1				= self.compute_ring_info(qradar_fs_1_ip)
		ring_info_fs_2				= self.compute_ring_info(qradar_fs_2_ip)
		ring_info_forescout			= self.compute_ring_info(qradar_forescout_ip)
		ring_info_wanfw 			= self.compute_ring_info(qradar_wanfw_ip)
		ring_info_tmds  			= self.compute_ring_info(qradar_tmds_ip)
		ring_info_extfw  			= self.compute_ring_info(qradar_extfw_ip)

		csv_data = []
		csv_data.append(['Attack Classification', 'Threat Source', 'Log Source', 'Ring 1 Event', 'Ring 1 Asset', 'Ring 2 Event', 'Ring 2 Asset', 'Ring 3 Event', 'Ring 3 Asset', 'Unidentified Event', 'Unidentified Asset', 'Total Event', 'Total Asset', 'Data Date'])

		the_ring = ring_info_if
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['External Hacking', 'External Threat', 'Internet Firewall', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_if, total_ring, report_date])

		the_ring = ring_info_incap
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['External Hacking', 'External Threat', 'Incapsula', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_incap, total_ring, report_date])
		
		#the_ring = ring_info_imperva
		#total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		#csv_data.append(['External Hacking', 'External Threat', 'WAF SecureSphere', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_imperva, total_ring, report_date]) 
		
		#the_ring = ring_info_palo
		#total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		#csv_data.append(['External Hacking', 'External Threat', 'Palo Alto VPN', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_palo, total_ring, report_date])
        
		the_ring = ring_info_extfw
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['External Hacking', 'External Threat', 'Extranet Firewall', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_extfw, total_ring, report_date])
		
		ironport_data = self.read_ironport_csv(report_date)
		if len(ironport_data) > 0:
			csv_data.append(ironport_data)
		
		the_ring = ring_info_dlp
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Data Leaked', 'Internal Threat', 'DLP McAfee', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_dlp, total_ring, report_date])
		
		the_ring = ring_info_officescan_1
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Malicious Code', 'Internal Threat', 'Trendmicro AV', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_officescan_1, total_ring, report_date]) 
		
		the_ring = ring_info_officescan_2
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Improper Usage', 'Internal Threat', 'Trendmicro AV', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_officescan_2, total_ring, report_date]) 
		
		the_ring = ring_info_edr
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Malicious Code', 'Internal Threat', 'EDR FireEye', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_edr, total_ring, report_date])
		
		the_ring = ring_info_proxy_1
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Malicious Code', 'Internal Threat', 'Proxy', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_proxy_1, total_ring, report_date])
		
		the_ring = ring_info_proxy_2
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Improper Usage', 'Internal Threat', 'Proxy', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_proxy_2, total_ring, report_date]) 
		
		the_ring = ring_info_fs_1
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Malicious Code', 'Internal Threat', 'Farm Server', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_fs_1, total_ring, report_date])
		
		the_ring = ring_info_fs_2
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Network Scanning (Internal)', 'Internal Threat', 'Farm Server', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_fs_2, total_ring, report_date])
		
		the_ring = ring_info_forescout
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Improper Usage', 'Internal Threat', 'ForeScout', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_forescout, total_ring, report_date])

		the_ring = ring_info_wanfw
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Improper Usage', 'Internal Threat', 'WAN Firewall', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_wanfw, total_ring, report_date])

		the_ring = ring_info_tmds
		total_ring = the_ring['ring']['ring1_ip'] + the_ring['ring']['ring2_ip'] + the_ring['ring']['ring3_ip'] + the_ring['ring']['unidentified_ip']
		csv_data.append(['Malicious Code', 'Internal Threat', 'TMDS', the_ring['ring']['ring1'], the_ring['ring']['ring1_ip'], the_ring['ring']['ring2'], the_ring['ring']['ring2_ip'], the_ring['ring']['ring3'], the_ring['ring']['ring3_ip'], the_ring['ring']['unidentified'], the_ring['ring']['unidentified_ip'], total_event_tmds, total_ring, report_date])
        
		# # logging
		csv_to_xls = {}

		csv_to_xls['Summary'] 						= csv_data
		csv_to_xls['Internet Firewall']				= raw_data_internet_firewall
		csv_to_xls['Incapsula']						= raw_data_incapsula
		#csv_to_xls['Imperva']						= raw_data_imperva
		#csv_to_xls['PaloAlto VPN']					= raw_data_palo_vpn
		csv_to_xls['DLP']							= raw_data_dlp
		csv_to_xls['Antivirus']						= raw_data_officescan_1 + raw_data_officescan_2
		csv_to_xls['EDR']							= raw_data_edr
		csv_to_xls['Proxy']							= raw_data_proxy_1 + raw_data_proxy_2
		csv_to_xls['Farm Server']					= raw_data_farm_server_1 + raw_data_farm_server_2
		csv_to_xls['ForeScout']						= raw_data_forescout
		csv_to_xls['WAN Firewall']					= raw_data_wanfw
		csv_to_xls['TMDS']						    = raw_data_tmds
		csv_to_xls['Extranet Firewall']			    = raw_data_extfw


		csv_to_xls['Internet Firewall (Asset)']		= ring_info_if['data']
		csv_to_xls['Incapsula (Asset)']				= ring_info_incap['data']
		#csv_to_xls['Imperva (Asset)']				= ring_info_imperva['data']
		#csv_to_xls['PaloAlto VPN (Asset)']			= ring_info_palo['data']
		csv_to_xls['DLP (Asset)']					= ring_info_dlp['data']

		if ring_info_officescan_1['data'] != ['No Data'] and ring_info_officescan_2['data'] != ['No Data']:
			ring_info_officescan_2['data'].pop(0)
			csv_to_xls['Antivirus (Asset)']				= ring_info_officescan_1['data'] + ring_info_officescan_2['data']
		elif ring_info_officescan_1['data'] == ['No Data'] and ring_info_officescan_2['data'] != ['No Data']:
			csv_to_xls['Antivirus (Asset)']				= ring_info_officescan_2['data']
		elif ring_info_officescan_1['data'] != ['No Data'] and ring_info_officescan_2['data'] == ['No Data']:
			csv_to_xls['Antivirus (Asset)']				= ring_info_officescan_1['data']
		else:
			csv_to_xls['Antivirus (Asset)']				= ['No Data']
	
		csv_to_xls['EDR (Asset)'] = ring_info_edr['data']

		if ring_info_proxy_1['data'] != ['No Data'] and ring_info_proxy_2['data'] != ['No Data']:
			ring_info_proxy_2['data'].pop(0)
			csv_to_xls['Proxy (Asset)']				= ring_info_proxy_1['data'] + ring_info_proxy_2['data']
		elif ring_info_proxy_1['data'] == ['No Data'] and ring_info_proxy_2['data'] != ['No Data']:
			csv_to_xls['Proxy (Asset)']				= ring_info_proxy_2['data']
		elif ring_info_proxy_1['data'] != ['No Data'] and ring_info_proxy_2['data'] == ['No Data']:
			csv_to_xls['Proxy (Asset)']				= ring_info_proxy_1['data']
		else:
			csv_to_xls['Proxy (Asset)']				= ['No Data']

		if ring_info_fs_1['data'] != ['No Data'] and ring_info_fs_2['data'] != ['No Data']:
			ring_info_fs_2['data'].pop(0)
			csv_to_xls['Farm Server (Asset)']				= ring_info_fs_1['data'] + ring_info_fs_2['data']
		elif ring_info_fs_1['data'] == ['No Data'] and ring_info_fs_2['data'] != ['No Data']:
			csv_to_xls['Farm Server (Asset)']				= ring_info_fs_2['data']
		elif ring_info_fs_1['data'] != ['No Data'] and ring_info_fs_2['data'] == ['No Data']:
			csv_to_xls['Farm Server (Asset)']				= ring_info_fs_1['data']
		else:
			csv_to_xls['Farm Server (Asset)']				= ['No Data']

		csv_to_xls['ForeScout (Asset)']	= ring_info_forescout['data']
		csv_to_xls['WAN Firewall (Asset)']	= ring_info_wanfw['data']
		csv_to_xls['TMDS (Asset)']	= ring_info_tmds['data']
		csv_to_xls['Extranet Firewall (Asset)']	= ring_info_extfw['data']
		
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
		table_metadata['name'] 		= 'cyberattack_daily_new_3' #switched from cyberattack_daily_new_2
		table_metadata['data date'] = time_period['start_time']

		# create and insert table
		self.create_mssql_table(connection, table_metadata)
		self.insert_mssql_table(connection, table_metadata)

		# VPN USER LOG
		#raw_data_vpn	= self.get_log(api_client, 'Palo VPN - Total User', time_period)
		#qradar_vpn 		= self.json2array(raw_data_vpn)
		
		#tmp = []
		#for y in qradar_vpn:
		#	tmp.append(y[0])

		#total_user_vpn = len(list(dict.fromkeys(tmp)))

		#header 	= ['Total', 'Data Date']
		#content = [total_user_vpn, start_time]

		#combined_data 	= [header, content]  

		#if len(combined_data) > 0:
		#	table_metadata				= self.examine_data(combined_data)
		#	table_metadata['name'] 		= 'vpn_total_user_daily'
		#	table_metadata['data date'] = time_period['start_time']

			# create and insert table
		#	self.create_mssql_table(connection, table_metadata)
		#	self.insert_mssql_table(connection, table_metadata)

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
		connection = pyodbc.connect('driver={ODBC Driver 17 for SQL Server};server=RVSIEMW1ABC19WP;database=Dashboard;uid=subes;pwd=Tableau@2020;ColumnEncryption=Enabled;')
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
		# print(params)
		# print(insert_query_expression)
		# params = [['External Hacking', 'External Threat', 'Internet Firewall', 202429, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'Incapsula', 122358, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'WAF SecureSphere', 139, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'Palo Alto VPN', 6, '2020-04-21 06:00:00'], [], ['Data Leaked', 'Internal Threat', 'DLP McAfee', 2, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'Trendmicro AV', 24637, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'Trendmicro AV', 119, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'EDR FireEye', 14817, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'Proxy', 7170, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'Proxy', 0, '2020-04-21 06:00:00'], ['Network Scanning (Internal)', 'Internal Threat', 'Farm Server', 9146, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'ForeScout', 0, '2020-04-21 06:00:00']]

		# print(insert_query_expression)

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
		# print(params)
		# print(insert_query_expression)
		# params = [['External Hacking', 'External Threat', 'Internet Firewall', 202429, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'Incapsula', 122358, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'WAF SecureSphere', 139, '2020-04-21 06:00:00'], ['External Hacking', 'External Threat', 'Palo Alto VPN', 6, '2020-04-21 06:00:00'], [], ['Data Leaked', 'Internal Threat', 'DLP McAfee', 2, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'Trendmicro AV', 24637, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'Trendmicro AV', 119, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'EDR FireEye', 14817, '2020-04-21 06:00:00'], ['Malicious Code', 'Internal Threat', 'Proxy', 7170, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'Proxy', 0, '2020-04-21 06:00:00'], ['Network Scanning (Internal)', 'Internal Threat', 'Farm Server', 9146, '2020-04-21 06:00:00'], ['Improper Usage', 'Internal Threat', 'ForeScout', 0, '2020-04-21 06:00:00']]

		# print(insert_query_expression)

		cursor.executemany(insert_query_expression, params)
		
		connection.commit()

		print("Completed process Table {}!".format(table_metadata['name']))

	def compute_total(self, data):
		total = 0

		for d in data:
			total += float(d[1])

		total = int(total)

		return total
	
	def compute_ring_info(self, data):
		ring 					= {}
		ring['ring1'] 			= 0
		ring['ring2'] 			= 0
		ring['ring3'] 			= 0
		ring['unidentified'] 	= 0

		ring['ring1_ip'] 			= 0
		ring['ring2_ip'] 			= 0
		ring['ring3_ip'] 			= 0
		ring['unidentified_ip'] 	= 0

		ring1_ip			= []
		ring2_ip			= []
		ring3_ip			= []
		unidentified_ip		= []

		ring1			= 0
		ring2 			= 0
		ring3			= 0
		unidentified	= 0

		total = 0

		if len(data) > 0:
			new_data 	= []
			header 		= data.pop(0)
			header 		= self.add_array_item_in_n_position(header, 1, 'Ring')

			new_data.append(header)
			
			# Based on AQL query selection column
			# row[0]: Asset IP
			# row[5]: Source IP
			# row[6]: Dest IP
			# row[7]: Ring Source IP
			# row[8]: Ring Dest IP
			
			for row in data:
				ring_info = ''
				# print(row)

				last_index = len(row) - 1

				source_ip_idx = last_index - 3
				dest_ip_idx = last_index - 2
				ring_source_ip = last_index - 1
				ring_dest_ip = last_index

				if row[0] == row[source_ip_idx]:
					ring_info = row[ring_source_ip]
				elif row[0] == row[dest_ip_idx]:
					ring_info = row[ring_dest_ip]

					
				
				if ring_info == 'Unknown':
					unidentified += float(row[1])
					unidentified_ip.append(row[0])
					ring_info = 'Unidentified'
				elif ring_info == 'R1':
					ring1 += float(row[1])
					ring1_ip.append(row[0])
					ring_info = 'Ring 1'
				elif ring_info == 'R2':
					ring2 += float(row[1])
					ring2_ip.append(row[0])
					ring_info = 'Ring 2'
				elif ring_info == 'R3':
					ring3 += float(row[1])
					ring3_ip.append(row[0])
					ring_info = 'Ring 3'
				
				# print(ring_info)

				row[1] = int(str(row[1]).replace('.0', ''))

				row = self.add_array_item_in_n_position(row, 1, ring_info)
				new_data.append(row)	

			data = new_data

		else:
			data = ['No Data']
		
		ring['ring1'] 			= int(ring1)
		ring['ring2'] 			= int(ring2)
		ring['ring3'] 			= int(ring3)
		ring['unidentified'] 	= int(unidentified)

		ring['ring1_ip'] 		= len(list(dict.fromkeys(ring1_ip)))
		ring['ring2_ip'] 		= len(list(dict.fromkeys(ring2_ip)))
		ring['ring3_ip'] 		= len(list(dict.fromkeys(ring3_ip)))
		ring['unidentified_ip'] = len(list(dict.fromkeys(unidentified_ip)))

		return {'data': data, 'ring': ring}


	def add_array_item_in_n_position(self, the_array, n, new_item):
		new_array = []
		counter = 0

		for item in the_array:
			if counter == n:
				new_array.append(new_item)

			new_array.append(item)

			counter += 1

		return new_array
		
	def combine_data(self, qradar_log, classification, data_date):
		csv_wannabe = []

		for log in qradar_log:
			if log[0] in classification:
				csv_wannabe.append([log[0]] + [classification[log[0]]] + [log[1]] + [data_date])

		return csv_wannabe

	def combine_data_with_date(self, qradar_log, data_date):
		is_header = True
		csv_wannabe = []

		for log in qradar_log:
			if is_header:
				csv_wannabe.append(log + ['Data Date'])
				is_header = False
				continue

			csv_wannabe.append(log + [data_date])

		return csv_wannabe

	def combine_col(self, qradar_log, col1, col2, data_date):
		header = []
		csv_wannabe = []

		for log in qradar_log:
			csv_wannabe.append([log[0]] + [col1] + [col2] + [log[1]] + [data_date])

		return csv_wannabe

	def get_log(self, api_client, log_source, time_period):

		if log_source == 'Internet Firewall':
			return self.get_json_log(api_client, self.get_internet_firewall_query(time_period))
		elif log_source == 'Internet Firewall IP':
			return self.get_json_log(api_client, self.get_internet_firewall_ip_query(time_period))
		elif log_source == 'EDR':
			return self.get_json_log(api_client, self.get_edr_query(time_period))
		elif log_source == 'EDR IP':
			return self.get_json_log(api_client, self.get_edr_ip_query(time_period))	
		elif log_source == 'Incapsula':
			return self.get_json_log(api_client, self.get_incapsula_query(time_period))
		elif log_source == 'Incapsula IP':
			return self.get_json_log(api_client, self.get_incapsula_ip_query(time_period))
		elif log_source == 'Officescan 1':
			return self.get_json_log(api_client, self.get_officescan_1_query(time_period))
		elif log_source == 'Officescan 1 IP':
			return self.get_json_log(api_client, self.get_officescan_1_ip_query(time_period))
		elif log_source == 'Officescan 2':
			return self.get_json_log(api_client, self.get_officescan_2_query(time_period))
		elif log_source == 'Officescan 2 IP':
			return self.get_json_log(api_client, self.get_officescan_2_ip_query(time_period))
		#elif log_source == 'Imperva Action':
		#	return self.get_json_log(api_client, self.get_imperva_action_query(time_period))
		#elif log_source == 'Imperva Action IP':
		#	return self.get_json_log(api_client, self.get_imperva_action_ip_query(time_period))
		elif log_source == 'Proxy 1':
			return self.get_json_log(api_client, self.get_proxy_1_query(time_period))
		elif log_source == 'Proxy 1 IP':
			return self.get_json_log(api_client, self.get_proxy_1_ip_query(time_period))
		elif log_source == 'Proxy 2':
			return self.get_json_log(api_client, self.get_proxy_2_query(time_period))	
		elif log_source == 'Proxy 2 IP':
			return self.get_json_log(api_client, self.get_proxy_2_ip_query(time_period))	
		#elif log_source == 'Palo VPN':
		#	return self.get_json_log(api_client, self.get_palo_vpn_query(time_period))
		#elif log_source == 'Palo VPN IP':
		#	return self.get_json_log(api_client, self.get_palo_vpn_ip_query(time_period))
		#elif log_source == 'Palo VPN - Total User':
		#	return self.get_json_log(api_client, self.get_palo_vpn_total_user_query(time_period))
		elif log_source == 'DLP':
			return self.get_json_log(api_client, self.get_dlp_query(time_period))
		elif log_source == 'DLP IP':
			return self.get_json_log(api_client, self.get_dlp_ip_query(time_period))
		elif log_source == 'Farm Server 1':
			return self.get_json_log(api_client, self.get_farm_server_1_query(time_period))
		elif log_source == 'Farm Server 1 IP':
			return self.get_json_log(api_client, self.get_farm_server_1_ip_query(time_period))
		elif log_source == 'Farm Server 2':
			return self.get_json_log(api_client, self.get_farm_server_2_query(time_period))
		elif log_source == 'Farm Server 2 IP':
			return self.get_json_log(api_client, self.get_farm_server_2_ip_query(time_period))
		elif log_source == 'ForeScout':
			return self.get_json_log(api_client, self.get_forescout_query(time_period))
		elif log_source == 'ForeScout IP':
			return self.get_json_log(api_client, self.get_forescout_ip_query(time_period))
		elif log_source == 'WAN Firewall':
			return self.get_json_log(api_client, self.get_wan_firewall_query(time_period))
		elif log_source == 'WAN Firewall IP':
			return self.get_json_log(api_client, self.get_wan_firewall_ip_query(time_period))
		elif log_source == 'TMDS':
			return self.get_json_log(api_client, self.get_tmds_query(time_period))
		elif log_source == 'TMDS IP':
			return self.get_json_log(api_client, self.get_tmds_ip_query(time_period))
		elif log_source == 'Extranet Firewall':
			return self.get_json_log(api_client, self.get_ext_firewall_query(time_period))
		elif log_source == 'Extranet Firewall IP':
			return self.get_json_log(api_client, self.get_ext_firewall_ip_query(time_period))
		elif log_source == 'Total Event':
			return self.get_json_log(api_client, self.get_total_event_query(time_period))

	def read_ironport_csv(self, data_date):
		# print('ironport')
		data = []

		path = os.path.realpath('summary_cyberattack')

		log_files = []

		for r, d, f in os.walk(path):
			for file in f:
				if 'ironport' in file:
					log_files.append(file)
		
		if len(log_files) == 0:
			return data
			
		with open(os.path.join(path, log_files.pop(0))) as csvfile:
			readCSV = csv.reader(csvfile, delimiter=',')
			for row in readCSV:
				# print(row)
				if data_date.split(' ')[0] in row[1]:
					# print(row[1])
					data =  ['Email Attack', 'External Threat', 'IronPort', 0, 0, 0, 0, 0, 0, 0, 0, int(row[0]), 0, data_date]
		
		# os.remove(os.path.join(path, file))

		return data

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

	def get_incapsula_query(self, time_period):

		query_expression = """
			SELECT 
			QIDNAME(qid) as "Event Name",
			SUM(eventcount) as "Event Count",
			"Incapsula: Traffic Type" as "Incapsula: Traffic Type",
			MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
			MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
			FROM events
			WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Incapsula'
			and not (RULENAME(creeventlist) = 'Incapsula - Exclude company.com')
			and not ("Incapsula: Traffic Type" = 'Normal')
			and REFERENCESETCONTAINS('Incapsula - High Severity Rules CTS',"Incapsula: Traffic Type")
			and ("Event Name" NOT LIKE '%REQ_BLOCKED%' AND "Event Name" NOT LIKE '%REQ_BAD%' AND "Event Name" NOT LIKE '%REQ_CHALLENGE%')
			GROUP BY "Event Name"
			ORDER BY "Event Count" DESC
			START '{0}' STOP '{1}'
			""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	#def get_imperva_action_query(self, time_period):
    #
	#	query_expression = """
	#		SELECT 
	#		"WAF: Alert Description" as "WAF: Alert Description",
	#		SUM(eventcount) as "Event Count",
	#		"WAF: Action" as "WAF: Action",
	#		"WAF: Severity" as "WAF: Severity",
	#		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
	#		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
	#		FROM events
	#		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'WAF'
	#		and "WAF: Alert Description" is not NULL
	#		and "WAF: Action" = 'None'
	#		and "WAF: Severity" = 'High'
	#		GROUP BY "WAF: Alert Description"
	#		ORDER BY "Event Count" DESC
	#		START '{0}' STOP '{1}'
	#		""".format(time_period['start_time'], time_period['end_time'])
    #
	#	return query_expression

	#def get_palo_vpn_query(self, time_period):
    #
	#	query_expression = """
	#		SELECT 
	#		QIDNAME(qid) as "Event Name",
	#		SUM(eventcount) as "Event Count",
	#		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
	#		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
	#		FROM events
	#		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Palo Alto - VPN'
	#		AND "PaloAlto: Category" = 'THREAT'
	#		AND "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
	#		AND "PaloAlto: Virtual Firewall" like 'vsys3'
	#		GROUP BY "Event Name"
	#		ORDER BY "Event Count" desc
	#		START '{0}' STOP '{1}'
	#		""".format(time_period['start_time'], time_period['end_time'])
    #
	#	return query_expression

	def get_edr_query(self, time_period):

		query_expression = """
			SELECT QIDNAME(qid) as "Event Name", 
			SUM(eventcount) as "Event Count",
			MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
			MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
			FROM events
			WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'FireEye'
			AND (qid = '55500011' or qid = '2000004' )
			AND ("HX-Resolution" not like '%quarantine%')
			AND NOT REFERENCESETCONTAINS('EDR_Exclude', destinationip)
            AND NOT ("HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SYMERR PROCESS (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%OPHION RANSOMWARE (FAMILY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS WRITE TO STARTUP DIRECTORY (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%TEXTTRANSFORM PARENT PROCESS (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SVCHOST.EXE A (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS WSCRIPT USAGE (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SYMERR PROCESS (METHODOLOGY)%'
            or "HX-IOCIndicatorOREventId" LIKE '%MDRTESTIOC_%'
            )
			AND "HX-IOCIndicatorOREventId" IS NOT NULL
			GROUP BY "Event Name"
			ORDER BY "Event Count" DESC
			START '{0}' STOP '{1}'
			""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	# Malicious Code 
	def get_officescan_1_query(self, time_period):

		query_expression = """
			SELECT 
			QIDNAME(qid) as "Event Name",
			SUM(eventcount) as "Event Count",
			"AV Result Action" as "AV Result Action",
			MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
			MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
			FROM events
			WHERE 
			LOGSOURCEGROUPNAME(devicegrouplist) = 'AntiVirus'
			AND REPLACEFIRST(' ', "AV Result Action", '') NOT IN ('Access Denied', 'Cleaned', 'Encrypted', 'Deleted', 'Quarantine')
			AND ("AV Result Action" not like '%(Delete)%' AND "AV Result Action" not like '%Access Denied%')
			AND "AV Result Action" IS NOT NULL
            AND NOT REFERENCESETCONTAINS('TrendMicro_Exclude',sourceip)
			GROUP BY "Event Name"
			ORDER BY "Event Count" DESC
			START '{0}' STOP '{1}'
			""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	# Improper Usage
	def get_officescan_2_query(self, time_period):

		query_expression = """
			SELECT 
			QIDNAME(qid) as "Event Name",
			SUM(eventcount) as "Event Count",
			"AV Result Action" as "AV Result Action",
			MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
			MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
			FROM events
			WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'AntiVirus'
			and CATEGORYNAME(category) = 'Application Policy Violation'
            AND NOT REFERENCESETCONTAINS('TrendMicro_Exclude',sourceip)
			GROUP BY "Event Name"
			ORDER BY "Event Count" DESC
			START '{0}' STOP '{1}'
			""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	# Malicious Code
	def get_proxy_1_query(self, time_period):

		query_expression = """
		SELECT
		QIDNAME(qid) as "Event Name",
		count(*) as "Event Count",
		"BlueCoat: Content Category" as "BlueCoat: Content Category",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Proxy123'
		and ("BlueCoat: Content Category" = 'Malicious_Outbound_Data/Botnets' 
		or "BlueCoat: Content Category" = 'Malicious_Sources/Malnets' 
		or "BlueCoat: Content Category" = 'Phishing' 
		or "BlueCoat: Content Category" = 'Compromised_Sites' 
		or "BlueCoat: Content Category" = 'Suspicious')
		AND "BlueCoat: HTTP Status Code" = 200
		AND "BlueCoat: HTTP Method" NOT LIKE '%CONNECT%'
		AND not ((sourceip = '10.254.152.103') and (destinationip = '103.139.83.21' or destinationip = '103.139.82.21') and  (destinationport = '443' or destinationport = '9777' or destinationport = '5555' or destinationport = '9999' or destinationport = '8888'))
        AND not (sourceip = '10.243.218.6')
		AND not (sourceip = '10.243.221.114')
        AND not REFERENCESETCONTAINS('Bluecoat Proxy CTS - URL Exclude',"BlueCoat: URL Hostname")
		GROUP BY "BlueCoat: Content Category"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	# Improper Usage
	def get_proxy_2_query(self, time_period):
		query_expression = """
		SELECT
		QIDNAME(qid) as "Event Name",
		SUM(eventcount) as "Event Count",
		"BlueCoat: Content Category" as "BlueCoat: Content Category",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Proxy'
		and ("BlueCoat: Content Category" = 'Proxy_Avoidance' 
		or "BlueCoat: Content Category" = 'Remote_Access'
		or "BlueCoat: Content Category" = 'Peer-to-Peer_(P2P)'
        or "BlueCoat: Content Category" = 'Malicious_Outbound_Data/Botnets' 
		or "BlueCoat: Content Category" = 'Malicious_Sources/Malnets' 
		or "BlueCoat: Content Category" = 'Phishing' 
		or "BlueCoat: Content Category" = 'Compromised_Sites' 
		or "BlueCoat: Content Category" = 'Suspicious')
		AND "BlueCoat: HTTP Status Code" = 200
		AND "BlueCoat: HTTP Method" NOT LIKE '%CONNECT%'	
        AND not ((sourceip = '10.254.152.103') and (destinationip = '103.139.83.21' or destinationip = '103.139.82.21') and  (destinationport = '443' or destinationport = '9777' or destinationport = '5555' or destinationport = '9999' or destinationport = '8888'))
        AND not (sourceip = '10.243.218.6')
		AND not (sourceip = '10.243.221.114')
        AND not REFERENCESETCONTAINS('Bluecoat Proxy CTS - URL Exclude',"BlueCoat: URL Hostname")
		GROUP BY "BlueCoat: Content Category" 
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	def get_dlp_query(self, time_period):

		query_expression = """
		SELECT
		QIDNAME(qid) as "Event Name",
		SUM(eventcount) as "Event Count",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'McAfee DLP'
		AND "DLP: Actual Action" LIKE '%No Action%'
		AND "DLP: Expected Action" LIKE '%Block%'
		AND "DLP: Failure Reason" NOT LIKE '%Bypass Mode%'
		AND "DLP: Failure Reason" NOT LIKE '%Time Exceeded%'
		AND "DLP: Classification Category" LIKE '%CONFIDENTIAL%'
		GROUP BY "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	# Malicious Code
	def get_farm_server_1_query(self, time_period):

		query_expression = """
		SELECT 
		QIDNAME(qid) as "Event Name",
		SUM(eventcount) as "Event Count",
		qid as QID,
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Farm Server Firewalls'
		and eventdirection = 'L2L'
		and (CATEGORYNAME(category) = 'Spyware Detected'
		or CATEGORYNAME(category) = 'Remote Code Execution'
		or CATEGORYNAME(category) = 'Virus Detected') 
		and "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
		and not REFERENCESETCONTAINS('FarmServer_Exclude',sourceip)
		and RULENAME(creeventlist) not like  '%Cyber Attack Summary - Exclude%'
		and RULENAME(creeventlist) = 'Ring1'
        and not ("Event Name" = 'Spyware Detected' and destinationport = '53')
		and not ((sourceip = '10.204.49.116') or (destinationip = '10.147.51.205') or  (destinationport = '22'))
        and "PaloAlto: Content Type" NOT LIKE '%wildfire%'
		GROUP BY "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	# Network Scanning (Internal)
	def get_farm_server_2_query(self, time_period):

		query_expression = """
		SELECT QIDNAME(qid) as "Event Name",
		SUM(eventcount) as "Event Count",
		qid as QID,
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Farm Server Firewalls'
		and eventdirection = 'L2L'
		and (CATEGORYNAME(category) = 'Misc Exploit'
		or CATEGORYNAME(category) = 'Brute force login'
		or CATEGORYNAME(category) = 'Access Denied' 
		or CATEGORYNAME(category) = 'Buffer Overflow'
		or CATEGORYNAME(category) = 'Firewall Deny' 
		or CATEGORYNAME(category) = 'Information Leak') 
		and "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
		and not REFERENCESETCONTAINS('FarmServer_Exclude',sourceip)
        and not ((sourceip = '10.254.196.105' or sourceip = '10.254.196.104' or sourceip = '10.254.196.75' or sourceip = '10.254.196.74' or sourceip = '10.204.53.212' or sourceip = '10.204.123.81' or sourceip = '10.204.123.77' or sourceip = '10.204.123.80' or sourceip = '10.204.124.46') and ("Event Name" = 'HTTP Unauthorized Brute Force Attack' or "Event Name" = 'HTTP: User Authentication Brute Force Attempt'))
		and RULENAME(creeventlist) not like '%Cyber Attack Summary - Exclude%'
		and RULENAME(creeventlist) = 'Ring1'
		and not ((sourceip = '10.204.49.116') or (destinationip = '10.147.51.205') or  (destinationport = '22'))
		GROUP BY "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	def get_forescout_query(self, time_period):

		query_expression = """
		SELECT
		QIDNAME(qid) as "Event Name",
		count(*) as "Event Count",
		"ForeScout: Property Value" as "ForeScout: Property Value",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		FROM events
	        WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'ForeScout' 
and ("ForeScout: Property Value" ilike '%No AV TM%' or "ForeScout: Property Value" ilike '%Unlegitimate SSID Direksi%' or "ForeScout: Property Value" ilike '%SSID Third Party used by Employee%' or "ForeScout: Property Value" ilike '%Non-AD User%' or "ForeScout: Property Value" ilike '%Hacking Tool Apps%') 
and not ("ForeScout: Property Value" like '%Unmatched%' or "ForeScout: Property Value" like '%Irresovable%' or "ForeScout: Property Value" like '%Pending%' or "ForeScout: Property Value" ilike '%No AV TM (Compliance TMDS)%') 
and not REFERENCESETCONTAINS('NAC_Exclude',sourceip) 
        and DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm')>='{0}' and DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm')<'{1}'
		GROUP BY "ForeScout: Property Value"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression

	def get_wan_firewall_query(self, time_period):

		query_expression = """
		SELECT QIDNAME(qid) as "Event Name",
		sum(eventcount) as "Event Count",
		qid as QID,
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'WAN Firewalls'
		AND (RULENAME(creeventlist) = 'BB: WAN - Threat Severity High or Critical' or RULENAME(creeventlist) = 'BB: WAN - Virus Detected')
		AND ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%')
		and not REFERENCESETCONTAINS('Exclude_IPVOICE',sourceip)
		GROUP BY "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression
        
	def get_tmds_query(self, time_period):

		query_expression = """
		SELECT
		QIDNAME(qid) as "Event Name",
		sum(eventcount) as "Event Count",
		"TMDS: Action" as "TMDS: Action",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'TMDS'
		AND "Event-Category" ILIKE '%intrusion%'
		AND ("TMDS: Severity" = '8' or "TMDS: Severity" = '9' or "TMDS: Severity" = '10')
		AND "TMDS: Action" NOT ILIKE '%reset%'
		GROUP BY "Event Name" 
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])

		return query_expression


	def get_ext_firewall_query(self, time_period):

		query_expression = """
		SELECT QIDNAME(qid) as "Event Name",
		sum(eventcount) as "Event Count",
		qid as QID,
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Extranet Firewalls'
        AND "PaloAlto: Category" = 'THREAT'
		AND ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%')
		GROUP BY "Event Name"
		ORDER BY "Event Count" desc
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


	# ======================================================================================================
	def get_internet_firewall_ip_query(self, time_period):

		query_expression = """
		SELECT
		destinationip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"PaloAlto: Category",
		"PaloAlto: Threat Severity",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Internet Firewalls'
		and eventdirection = 'R2L'
		and qid not in ('53506835')
		and "PaloAlto: Category" = 'THREAT'
		and ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%') 
        AND RULENAME(creeventlist) not like '%Filetype not NA%'
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" DESC
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	def get_edr_ip_query(self, time_period):
		query_expression = """
		SELECT
		destinationip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'FireEye'
		AND (qid = '55500011' or qid = '2000004' )
		AND ("HX-Resolution" not like '%quarantine%')
		AND NOT REFERENCESETCONTAINS('EDR_Exclude', destinationip)
        AND NOT ("HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SYMERR PROCESS (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%OPHION RANSOMWARE (FAMILY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS WRITE TO STARTUP DIRECTORY (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%TEXTTRANSFORM PARENT PROCESS (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SVCHOST.EXE A (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS WSCRIPT USAGE (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%SUSPICIOUS SYMERR PROCESS (METHODOLOGY)%'
        or "HX-IOCIndicatorOREventId" LIKE '%MDRTESTIOC_%'
        )
		AND "HX-IOCIndicatorOREventId" IS NOT NULL
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" DESC
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	def get_officescan_1_ip_query(self, time_period):
		query_expression = """
		SELECT
		sourceip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"AV Result Action" as "AV Result Action",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE 
		LOGSOURCEGROUPNAME(devicegrouplist) = 'AntiVirus'
		AND REPLACEFIRST(' ', "AV Result Action", '') NOT IN ('Access Denied', 'Cleaned', 'Encrypted', 'Deleted', 'Quarantine')
		AND ("AV Result Action" not like '%(Delete)%' 
		AND "AV Result Action" not like '%Access Denied%')
		AND "AV Result Action" IS NOT NULL
        AND NOT REFERENCESETCONTAINS('TrendMicro_Exclude',sourceip)
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" DESC
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	def get_officescan_2_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP", 
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'AntiVirus'
		and CATEGORYNAME(category) = 'Application Policy Violation'
        AND NOT REFERENCESETCONTAINS('TrendMicro_Exclude',sourceip)
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" DESC
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	def get_incapsula_ip_query(self, time_period):
		query_expression = """
		SELECT 
		destinationip as "Asset IP", 
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"Incapsula: Traffic Type" as "Incapsula: Traffic Type",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Incapsula'
		and not (RULENAME(creeventlist) = 'Incapsula - Exclude Branchless.company.com')
		and not ("Incapsula: Traffic Type" = 'Normal')
		and REFERENCESETCONTAINS('Incapsula - High Severity Rules CTS',"Incapsula: Traffic Type")
		and ("Event Name" NOT LIKE '%REQ_BLOCKED%' AND "Event Name" NOT LIKE '%REQ_BAD%' AND "Event Name" NOT LIKE '%REQ_CHALLENGE%')
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" DESC
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	#def get_imperva_action_ip_query(self, time_period):
	#	query_expression = """
	#	SELECT 
	#	destinationip as "Asset IP",
	#	SUM(eventcount) as "Event Count",
	#	"WAF: Alert Description" as "WAF: Alert Description",
	#	"WAF: Action" as "WAF: Action",
	#	"WAF: Severity" as "WAF: Severity",
	#	MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
	#	MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
	#	'{0}' as "Data Date",
	#	sourceip as "Source IP",
	#	destinationip as "Destination IP",
	#	CASE
	#		WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
	#		WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
	#		WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
	#		ELSE 'Unknown'
	#	END as "Ring Source",
	#	CASE
	#		WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
	#		WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
	#		WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
	#		ELSE 'Unknown'
	#	END as "Ring Destination"
	#	FROM events
	#	WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'WAF'
	#	and "WAF: Alert Description" is not NULL
	#	and "WAF: Action" = 'None'
	#	and "WAF: Severity" = 'High'
	#	GROUP BY sourceip, destinationip, "WAF: Alert Description"
	#	ORDER BY "Event Count" DESC
	#	START '{0}' STOP '{1}'
	#	""".format(time_period['start_time'], time_period['end_time'])
	#	
	#	return query_expression

	# Malicious Code
	def get_proxy_1_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP", 
		count(*) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"BlueCoat: Content Category" as "BlueCoat: Content Category",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		"BlueCoat: URL Hostname" as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Proxy123'
		and ("BlueCoat: Content Category" = 'Malicious_Outbound_Data/Botnets' 
		or "BlueCoat: Content Category" = 'Malicious_Sources/Malnets' 
		or "BlueCoat: Content Category" = 'Phishing' 
		or "BlueCoat: Content Category" = 'Compromised_Sites' 
		or "BlueCoat: Content Category" = 'Suspicious')
		AND "BlueCoat: HTTP Status Code" = 200
		AND "BlueCoat: HTTP Method" NOT LIKE '%CONNECT%'
		AND not ((sourceip = '10.254.152.103') and (destinationip = '103.139.83.21' or destinationip = '103.139.82.21') and  (destinationport = '443' or destinationport = '9777' or destinationport = '5555' or destinationport = '9999' or destinationport = '8888'))
        AND not (sourceip = '10.243.218.6')
		AND not (sourceip = '10.243.221.114')
        AND not REFERENCESETCONTAINS('Bluecoat Proxy CTS - URL Exclude',"BlueCoat: URL Hostname")
		GROUP BY sourceip, destinationip, "BlueCoat: Content Category" 
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	# Improper Usage
	def get_proxy_2_ip_query(self, time_period):
		query_expression = """
		SELECT
		sourceip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"BlueCoat: Content Category" as "BlueCoat: Content Category",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Proxy'
		and ("BlueCoat: Content Category" = 'Proxy_Avoidance' 
		or "BlueCoat: Content Category" = 'Remote_Access'
		or "BlueCoat: Content Category" = 'Peer-to-Peer_(P2P)'
        or "BlueCoat: Content Category" = 'Malicious_Outbound_Data/Botnets' 
		or "BlueCoat: Content Category" = 'Malicious_Sources/Malnets' 
		or "BlueCoat: Content Category" = 'Phishing' 
		or "BlueCoat: Content Category" = 'Compromised_Sites' 
		or "BlueCoat: Content Category" = 'Suspicious')
		AND "BlueCoat: HTTP Status Code" = 200
		AND "BlueCoat: HTTP Method" NOT LIKE '%CONNECT%'	
        AND not ((sourceip = '10.254.152.103') and (destinationip = '103.139.83.21' or destinationip = '103.139.82.21') and  (destinationport = '443' or destinationport = '9777' or destinationport = '5555' or destinationport = '9999' or destinationport = '8888'))
        AND not (sourceip = '10.243.218.6')
		AND not (sourceip = '10.243.221.114')
        AND not REFERENCESETCONTAINS('Bluecoat Proxy CTS - URL Exclude',"BlueCoat: URL Hostname")
		GROUP BY sourceip, destinationip, "BlueCoat: Content Category" 
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	#def get_palo_vpn_ip_query(self, time_period):
	#	query_expression = """
	#	SELECT 
	#	destinationip as "Asset IP",
	#	SUM(eventcount) as "Event Count",
	#	QIDNAME(qid) as "Event Name",
	#	MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
	#	MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
	#	'{0}' as "Data Date",
	#	sourceip as "Source IP",
	#	destinationip as "Destination IP",
	#	CASE
	#		WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
	#		WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
	#		WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
	#		ELSE 'Unknown'
	#	END as "Ring Source",
	#	CASE
	#		WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
	#		WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
	#		WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
	#		ELSE 'Unknown'
	#	END as "Ring Destination"
	#	FROM events
	#	WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Palo Alto - VPN'
	#	AND "PaloAlto: Category" = 'THREAT'
	#	AND "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
	#	AND "PaloAlto: Virtual Firewall" like 'vsys3'
	#	GROUP BY sourceip, destinationip, "Event Name"
	#	ORDER BY "Event Count" desc
	#	START '{0}' STOP '{1}'
	#	""".format(time_period['start_time'], time_period['end_time'])
	#	
	#	return query_expression

	def get_dlp_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'McAfee DLP'
		AND "DLP: Actual Action" LIKE '%No Action%'
		AND "DLP: Expected Action" LIKE '%Block%'
		AND "DLP: Failure Reason" NOT LIKE '%Bypass Mode%'
		AND "DLP: Failure Reason" NOT LIKE '%Time Exceeded%'
		AND "DLP: Classification Category" LIKE '%CONFIDENTIAL%'
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	# Malicious Code
	def get_farm_server_1_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Farm Server Firewalls'
		and eventdirection = 'L2L'
		and (CATEGORYNAME(category) = 'Spyware Detected' 
		or CATEGORYNAME(category) = 'Remote Code Execution'
		or CATEGORYNAME(category) = 'Virus Detected') 
		and "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
		and not REFERENCESETCONTAINS('FarmServer_Exclude',sourceip)
		and RULENAME(creeventlist) not like '%Cyber Attack Summary - Exclude%'
		and RULENAME(creeventlist) = 'Ring1'
        and not ("Event Name" = 'Spyware Detected' and destinationport = '53')
		and not ((sourceip = '10.204.49.116') or (destinationip = '10.147.51.205') or  (destinationport = '22'))
        and "PaloAlto: Content Type" NOT LIKE '%wildfire%'
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	# Network Scanning
	def get_farm_server_2_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP",
		SUM(eventcount) as "Event Count",
		QIDNAME(qid) as "Event Name",
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Farm Server Firewalls'
		and eventdirection = 'L2L'
		and (CATEGORYNAME(category) = 'Misc Exploit'
		or CATEGORYNAME(category) = 'Brute force login'
		or CATEGORYNAME(category) = 'Access Denied' 
		or CATEGORYNAME(category) = 'Buffer Overflow'
		or CATEGORYNAME(category) = 'Firewall Deny' 
		or CATEGORYNAME(category) = 'Information Leak') 
		and "PaloAlto: Action" NOT IN ('reset-both', 'drop', 'deny')
		and not REFERENCESETCONTAINS('FarmServer_Exclude',sourceip)
        and not ((sourceip = '10.254.196.105' or sourceip = '10.254.196.104' or sourceip = '10.254.196.75' or sourceip = '10.254.196.74' or sourceip = '10.204.53.212' or sourceip = '10.204.123.81' or sourceip = '10.204.123.77' or sourceip = '10.204.123.80' or sourceip = '10.204.124.46') and ("Event Name" = 'HTTP Unauthorized Brute Force Attack' or "Event Name" = 'HTTP: User Authentication Brute Force Attempt'))
		and RULENAME(creeventlist) not like '%Cyber Attack Summary - Exclude%'
		and RULENAME(creeventlist) = 'Ring1'
		and not ((sourceip = '10.204.49.116') or (destinationip = '10.147.51.205') or  (destinationport = '22'))
		GROUP BY sourceip, destinationip, "Event Name"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression

	def get_forescout_ip_query(self, time_period):
		query_expression = """
		SELECT 
		sourceip as "Asset IP",
		count(*) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"ForeScout: Property Value" as "ForeScout: Property Value",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		FROM events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'ForeScout' 
and ("ForeScout: Property Value" ilike '%No AV TM%' or "ForeScout: Property Value" ilike '%Unlegitimate SSID Direksi%' or "ForeScout: Property Value" ilike '%SSID Third Party used by Employee%' or "ForeScout: Property Value" ilike '%Non-AD User%' or "ForeScout: Property Value" ilike '%Hacking Tool Apps%') 
and not ("ForeScout: Property Value" like '%Unmatched%' or "ForeScout: Property Value" like '%Irresovable%' or "ForeScout: Property Value" like '%Pending%' or "ForeScout: Property Value" ilike '%No AV TM (Compliance TMDS)%') 
and not REFERENCESETCONTAINS('NAC_Exclude',sourceip) 
        and DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm')>='{0}' and DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm')<'{1}'
		GROUP BY sourceip, destinationip, "ForeScout: Property Value"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		
		return query_expression
        
	def get_wan_firewall_ip_query(self, time_period):
		query_expression = """
		SELECT
		sourceip as "Asset IP",
		count(*) as "Event Count",
		QIDNAME(qid) as "Event Name",
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'WAN Firewalls'
		AND (RULENAME(creeventlist) = 'BB: WAN - Threat Severity High or Critical' or RULENAME(creeventlist) = 'BB: WAN - Virus Detected')
		AND ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%')
		and not REFERENCESETCONTAINS('Exclude_IPVOICE',sourceip)
		GROUP BY "sourceip", "Event Name", "destinationip"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		return query_expression

	def get_tmds_ip_query(self, time_period):
		query_expression = """
		SELECT
		sourceip as "Asset IP",
		count(*) as "Event Count",
		QIDNAME(qid) as "Event Name",
		"TMDS: Action" as "TMDS: Action",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'TMDS'
		AND "Event-Category" ILIKE '%intrusion%'
		AND ("TMDS: Severity" = '8' or "TMDS: Severity" = '9' or "TMDS: Severity" = '10')
		AND "TMDS: Action" NOT ILIKE '%reset%'
		GROUP BY "sourceip", "Event Name"  
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		return query_expression

	def get_ext_firewall_ip_query(self, time_period):
		query_expression = """
		SELECT
		sourceip as "Asset IP",
		count(*) as "Event Count",
		QIDNAME(qid) as "Event Name",
		CATEGORYNAME(category) as "CATEGORYNAME(category)",
		MIN(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Start Time",
		MAX(DATEFORMAT(startTime, 'E dd-MM-yyyy HH:mm a')) as "Last Time",
		'{0}' as "Data Date",
		sourceip as "Source IP",
		destinationip as "Destination IP",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',sourceip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',sourceip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',sourceip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Source",
		CASE
			WHEN REFERENCESETCONTAINS('Ring_1_cts',destinationip) THEN 'R1'
			WHEN REFERENCESETCONTAINS('Ring_2_cts',destinationip) THEN 'R2'
			WHEN REFERENCESETCONTAINS('Ring_3_cts',destinationip) THEN 'R3'
			ELSE 'Unknown'
		END as "Ring Destination"
		from events
		WHERE LOGSOURCEGROUPNAME(devicegrouplist) = 'Extranet Firewalls'
		AND "PaloAlto: Category" = 'THREAT'
		AND ("PAloAlto: Action" LIKE '%alert%' or "PAloAlto: Action" LIKE '%allow%')
		GROUP BY "sourceip", "Event Name", "destinationip"
		ORDER BY "Event Count" desc
		START '{0}' STOP '{1}'
		""".format(time_period['start_time'], time_period['end_time'])
		return query_expression


	# ===============================
	def create_xlsx(self, data, filename):
		output_path		= os.path.realpath('user_log')

		workbook 			= xlsxwriter.Workbook(os.path.join(output_path, filename))
		summary 			= workbook.add_worksheet('Summary')
		internet_fw			= workbook.add_worksheet('Internet Firewall (Event)')
		internet_fw_asset 	= workbook.add_worksheet('Internet Firewall (Asset)')
		incapsula 			= workbook.add_worksheet('Incapsula (Event)')
		incapsula_asset		= workbook.add_worksheet('Incapsula (Asset)')
		#imperva 			= workbook.add_worksheet('Imperva (Event)')
		#imperva_asset		= workbook.add_worksheet('Imperva (Asset)')
		#palo_vpn 			= workbook.add_worksheet('PaloAlto VPN (Event)')
		#palo_vpn_asset		= workbook.add_worksheet('PaloAlto VPN (Asset)')
		extfw       		= workbook.add_worksheet('Extranet Firewall (Event)')
		extfw_asset   		= workbook.add_worksheet('Extranet Firewall (Asset)')
		dlp 				= workbook.add_worksheet('DLP (Event)')
		dlp_asset			= workbook.add_worksheet('DLP (Asset)')
		av 					= workbook.add_worksheet('Antivirus (Event)')
		av_asset			= workbook.add_worksheet('Antivirus (Asset)')
		edr 				= workbook.add_worksheet('EDR (Event)')
		edr_asset			= workbook.add_worksheet('EDR (Asset)')
		proxy 				= workbook.add_worksheet('Proxy (Event)')
		proxy_asset			= workbook.add_worksheet('Proxy (Asset)')
		farm_server			= workbook.add_worksheet('Farm Server (Event)')
		farm_server_asset	= workbook.add_worksheet('Farm Server (Asset)')
		forescout			= workbook.add_worksheet('ForeScout (Event)')
		forescout_asset		= workbook.add_worksheet('ForeScout (Asset)')
		wanfw   			= workbook.add_worksheet('WAN Firewall (Event)')
		wanfw_asset 		= workbook.add_worksheet('WAN Firewall (Asset)')
		tmds       			= workbook.add_worksheet('TMDS (Event)')
		tmds_asset   		= workbook.add_worksheet('TMDS (Asset)')
        
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
		self.write_raw_data_in_sheet(incapsula, data['Incapsula'], format_text)
		#self.write_raw_data_in_sheet(imperva, data['Imperva'], format_text)
		#self.write_raw_data_in_sheet(palo_vpn, data['PaloAlto VPN'], format_text)
		self.write_raw_data_in_sheet(dlp, data['DLP'], format_text)
		self.write_raw_data_in_sheet(av, data['Antivirus'], format_text)
		self.write_raw_data_in_sheet(edr, data['EDR'], format_text)
		self.write_raw_data_in_sheet(proxy, data['Proxy'], format_text)
		self.write_raw_data_in_sheet(farm_server, data['Farm Server'], format_text)
		self.write_raw_data_in_sheet(forescout, data['ForeScout'], format_text)
		self.write_raw_data_in_sheet(wanfw, data['WAN Firewall'], format_text)
		self.write_raw_data_in_sheet(tmds, data['TMDS'], format_text)
		self.write_raw_data_in_sheet(extfw, data['Extranet Firewall'], format_text)

		self.write_raw_data_in_sheet_array(internet_fw_asset, data['Internet Firewall (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(incapsula_asset, data['Incapsula (Asset)'], format_text)
		#self.write_raw_data_in_sheet_array(imperva_asset, data['Imperva (Asset)'], format_text)
		#self.write_raw_data_in_sheet_array(palo_vpn_asset, data['PaloAlto VPN (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(dlp_asset, data['DLP (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(av_asset, data['Antivirus (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(edr_asset, data['EDR (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(proxy_asset, data['Proxy (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(farm_server_asset, data['Farm Server (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(forescout_asset, data['ForeScout (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(wanfw_asset, data['WAN Firewall (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(tmds_asset, data['TMDS (Asset)'], format_text)
		self.write_raw_data_in_sheet_array(extfw_asset, data['Extranet Firewall (Asset)'], format_text)
		
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
