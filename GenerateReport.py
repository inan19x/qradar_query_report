import sys
import re 

regex = '[^@]+@[^@]+\.[^@]+'

from datetime import datetime, timedelta

sys.path.append(".")
from GetReport import MyReport

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

if __name__ == "__main__":
    starting_date = None 
    ending_date = None

    flag = True
    while flag:
        starting_date = input("Enter starting date (YYYY-MM-DD HH:mm:ss): ")
        flag = check_date_format(starting_date)

    flag = True
    while flag:
        ending_date = input("Enter ending date (YYYY-MM-DD HH:mm:ss): ")
        flag = check_date_format(ending_date)

        if not flag:
            flag = compare_start_end_date(starting_date, ending_date)

    myreport = MyReport(starting_date, ending_date)
    print('Generating report...')
    myreport.run()
    print('Report successfully generated!')

