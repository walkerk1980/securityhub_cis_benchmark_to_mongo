#!/usr/bin/env python3
import json
import sys
from datetime import date
from datetime import timedelta
import argparse
import logging
import boto3
from mongo_functions import *

MONGO_HOST = 'localhost'
MONGO_PORT = 27017
region = 'us-west-2'

argparser = argparse.ArgumentParser()
argparser.add_argument('-r','--region', nargs='?', const='NO', default=region, help='The AWS Region where Security Hub is running')
argparser.add_argument('-d', '--debug', nargs='?', const='NO', help='Debug log mode. WARNING!!! Log file can be very large!')
argparser.add_argument('-h', '--host', nargs='?', const='NO', default=MONGO_HOST, help='Mongo Host')
argparser.add_argument('-p', '--port', nargs='?', const='NO', default=MONGO_PORT, help='Mongo Port')
args = argparser.parse_args()

if args.debug:
    logging.basicConfig(format = '%(asctime)s %(name)s %(levelname)s %(message)s', filename = 'ingestor.log', filemode='w', level = logging.DEBUG)

collections = setup_mongo(MONGO_HOST, MONGO_PORT)

cis_bm_metadata = collections.get('cis_bm_metadata')
account_list = collections.get('account_list')
findings_col = collections.get('findings')
compensating_controls = collections.get('compensating_controls')

session = boto3.Session(region_name=args.region)

sh = session.client('securityhub')

paginator = sh.get_paginator('get_findings')

possible_finding_keys = ['SchemaVersion', 'Id', 'ProductArn', 'GeneratorId', 'AwsAccountId',
  'Types', 'FirstObservedAt', 'LastObservedAt', 'CreatedAt', 'UpdatedAt', 'Severity',
  'Title', 'Description', 'Remediation', 'ProductFields', 'Resources', 'Compliance',
  'WorkflowState', 'Workflow', 'RecordState'
]
finding_metadata_we_care_about = ['Severity', 'Title','Description','Remediation','Compliance', 'GeneratorId']
finding_keys_we_care_about = ['AwsAccountId', 'FirstObservedAt','LastObservedAt', 'Severity', 'Title','Description','Remediation','Compliance','RecordState', 'GeneratorId']
finding_status_keys = ['AwsAccountId', 'LastObservedAt', 'UpdatedAt', 'Compliance', 'GeneratorId', 'Severity']

findings_filter = {}

generator_id = 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/'
generator_id_filter = {
  'GeneratorId': [{
    'Value': generator_id,
    'Comparison': 'PREFIX'
  }
]}
findings_filter.update(generator_id_filter)

yesterday = date.today() - timedelta(days=1)
tomorrow = date.today() + timedelta(days=1)
updated_at_start = yesterday.isoformat()
updated_at_end = tomorrow.isoformat()
updated_at_filter_1 = {
  'UpdatedAt': [{
    'DateRange': {
      'Value': 1,
      'Unit': 'DAYS'
     }
   }]
}
updated_at_filter_2 = {
  'UpdatedAt': [{
    'Start': updated_at_start,
    'End': updated_at_end,
   }]
}
findings_filter.update(updated_at_filter_1)


def initial_db_populate(key_array, collection):
  logging.debug('Populating DB with Findings MetaData')
  findings_document = {"Findings": []}
  for page in paginator.paginate(Filters=findings_filter):
    for finding in page.get('Findings'):
      output_finding = {}
      [(output_finding.update({item: finding.get(item)})) for item in finding.keys() if item in key_array ]
      findings_document['Findings'].append(output_finding)
      # print(output_finding.get('Title'))
    count_in_collection = insert_finding_metadata_into_db(collection, findings_document)
    if count_in_collection > 42:
      break

def populate_periodic_account_status(key_array, collection):
  logging.debug('Populating DB with Account Findings')
  findings_document = {"Findings": []}
  for page in paginator.paginate(Filters=findings_filter):
    for finding in page.get('Findings'):
      output_finding = {}
      [(output_finding.update({item: finding.get(item)})) for item in finding.keys() if item in key_array ]
      findings_document['Findings'].append(output_finding)
    insert_finding_status_into_db(collection, findings_document)
    #print(findings_document)

if __name__ == '__main__':
  initial_db_populate(finding_metadata_we_care_about, cis_bm_metadata)
  populate_periodic_account_status(finding_status_keys, findings_col)
  update_account_list_col_in_db(findings_col, account_list)
