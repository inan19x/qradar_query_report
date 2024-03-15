import sys
import re 

regex = '[^@]+@[^@]+\.[^@]+'

from datetime import datetime, timedelta

sys.path.append(".")
from GetQuery import GetQueryResult
from SendEmail import SendEmailReport

def check_date_format(date_input):
	flag = True
	try:
		date = datetime.strptime(date_input, "%Y-%m-%d %H:%M:%S")
		flag = False
	except:
		print('Input date is in wrong format!')

	return flag

def compare_start_end_date(start_date, end_date):
	flag = True

	start_date = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
	end_date = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
	
	if start_date > end_date:
		flag = True
		print('Ending date cannot be before starting date!')
	elif start_date == end_date:
		flag = True
		print('Ending date cannot be the same as starting date!')
	else:
		flag = False

	return flag

def check_email(email):
	flag = True 

	if re.search(regex, email):  
		print("Valid Email")  
		flag = False
	else:  
		print("Invalid Email") 
		flag = True

	return flag

if __name__ == "__main__":
	starting_date = None
	ending_date = None
	email_address = None

	flag = True
	while flag:
		starting_date = input("Enter starting date (ex: YYYY-MM-DD HH:mm:ss): ")
		flag = check_date_format(starting_date)

	flag = True
	while flag:
		ending_date = input("Enter ending date (YYYY-MM-DD HH:mm:ss): ")
		flag = check_date_format(ending_date)

		if not flag:
			flag = compare_start_end_date(starting_date, ending_date)

	flag = True
	while flag:
		email_address = input("Enter email addresss (ex: qradar_admin@examplecompany.com): ")
		flag = check_email(email_address)

	myreport	= GetQueryResult(starting_date, ending_date)
	print('Generating report...')
	myreport.run()
	print('Report successfully generated!')

	mymail  = SendEmailReport(starting_date, ending_date, email_address)
	print('Sending report...')
	mymail.run()
	print('Report sent to {0}!'.format(email_address))
