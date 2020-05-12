#!/usr/bin/env python3
import logging
try:
  from pymongo import MongoClient
except ModuleNotFoundError:
  print('pymongo module must be installed via pip')
  exit(1)

def get_mongo_client(mongo_host, mongo_port):
  logging.debug('Connecting to MongoDb at {0} {1}'.format(mongo_host, mongo_port))
  mongo_client = MongoClient(mongo_host, mongo_port)
  return(mongo_client)

def setup_mongo(mongo_host, mongo_port):
  mongo = get_mongo_client(mongo_host, mongo_port)
  db = mongo.compliance
  cis_bm_metadata = db.cis_benchmark_static_metadata_col
  account_list = db.aws_accounts_col
  findings = db.findings_col
  compensating_controls = db.compensating_controls_col
  return({
    'cis_bm_metadata': cis_bm_metadata,
    'account_list': account_list,
    'findings': findings,
    'compensating_controls': compensating_controls,
  })

def insert_finding_metadata_into_db(findings_col, findings_dict):
  [ ( findings_col.insert_one(x) ) for x in findings_dict.get('Findings') if not findings_col.find_one({"Title": x.get('Title')}) ]
  findings_count = findings_col.count()
  print('Compliance Metadat Controls in collection: ' + str(findings_count))
  return findings_count

def insert_finding_status_into_db(findings_col, findings_dict):
  [ ( findings_col.insert_one(x) ) for x in findings_dict.get('Findings')
    if not findings_col.find_one({
        "GeneratorId": x.get('GeneratorId'),
        "AwsAccountId": x.get('AwsAccountId'),
        "LastObservedAt": x.get('LastObservedAt'),
        "UpdatedAt": x.get('UpdatedAt')
      })
  ]
  findings_count = findings_col.count()
  print('Findings in collection: ' + str(findings_count))
  return findings_count

def update_account_list_col_in_db(findings_col, account_list_col):
  unique_accounts = findings_col.distinct('AwsAccountId')
  [ ( account_list_col.insert_one({"AwsAccountId": x}) ) for x in unique_accounts
    if not account_list_col.find_one({
        "AwsAccountId": x
      })
  ]
  accounts_count = account_list_col.count()
  print('Accounts in collection: ' + str(accounts_count))
  return accounts_count

def insert_compensating_control():
  pass
