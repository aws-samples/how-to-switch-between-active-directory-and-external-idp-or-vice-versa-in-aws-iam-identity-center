#! /usr/bin/python3
import argparse
import csv
import logging
import pprint
import sys
import time

import boto3
from botocore.exceptions import ClientError

pp = pprint.PrettyPrinter()


def init_clp(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-l', '--list', action='store_true',
                        help='Returns all permission set to account assignment information.')
    parser.add_argument('-p', '--principals', action='store_true',
                        help='Returns all user and group principals found in AWS IAM Identity Center.')
    parser.add_argument('-s', '--set', action='store_true',
                        help='Assign permission sets to AWS accounts and groups/users. '
                             + 'Use -c to stay in a loop checking request results instead of exiting immediately.')
    parser.add_argument('-c', '--check', action='store_true',
                        help='Requires -s to work. Loops checking the assignment request status every few seconds.')
    parser.add_argument('-o', '--output', type=str, default='output.csv',
                        help='Output file for -l --list, -p --principals.')
    parser.add_argument('-i', '--input', type=str, default='input.csv',
                        help='Input file for -s --set.')
    parser.add_argument('-d', '--debug', type=str, default='',
                        help='Debug log file, always utilize the highest verbosity possible for the log messages.')
    parser.add_argument('--profile', type=str, default='',
                        help='AWS Session profile name (when using named profiles instead of default).')

    args = parser.parse_args(args=argv)
    return args


# Returns 2 strings: Identity Store instance ARN, Identity Store ID
def get_idc_instance_information(boto_session):
    logger = logging.getLogger(get_idc_instance_information.__name__)
    logger.info('Retrieving IDC instance information')
    try:
        client = boto_session.client('sso-admin')
        instances_list = client.list_instances(
            MaxResults=1,
        )
        logger.info(f'  Response: \n{pp.pformat(instances_list)}')
        instances = instances_list.get('Instances')
    except ClientError as e:
        raise e
    if len(instances) < 1:
        raise LookupError
    return instances[0].get('InstanceArn'), instances[0].get('IdentityStoreId')


# Returns dictionary dict[Permission Set ARN] = Permission Set structure as per
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/list_permission_sets.html
# 2nd return value dict[Permission Set Name] = Permission Set structure.
def list_permission_sets(boto_session, idc_arn):
    logger = logging.getLogger(list_permission_sets.__name__)
    logger.info('Retrieving IDC Permission Sets')
    try:
        dict_permission_sets_arn, dict_permissions_sets_name = {}, {}
        client = boto_session.client('sso-admin')
        paginator = client.get_paginator('list_permission_sets')
        response_iterator = paginator.paginate(InstanceArn=str(idc_arn))
        for response in response_iterator:
            for permission_set_arn in response.get('PermissionSets', []):
                logger.info(f'  Retrieving IDC Permission Set details for {permission_set_arn}')
                response = client.describe_permission_set(
                    InstanceArn=idc_arn,
                    PermissionSetArn=permission_set_arn
                )
                permission_set = response.get('PermissionSet', None)
                if permission_set is not None:
                    ps_name = permission_set.get('Name')
                    logger.info(f'  Retrieved: {ps_name}')
                    logger.info(f'  Response: \n{pp.pformat(response)}')
                    dict_permission_sets_arn[permission_set_arn] = permission_set
                    dict_permissions_sets_name[ps_name] = permission_set
                else:
                    logger.error(f'  No permission set found for {permission_set_arn}')
    except ClientError as e:
        raise e
    return dict_permission_sets_arn, dict_permissions_sets_name


# Returns dictionary dict[account ID] = Account structure as per
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/client/list_accounts.html
def list_accounts(boto_session):
    logger = logging.getLogger(list_accounts.__name__)
    logger.info('Retrieving AWS Organization accounts')
    dict_accounts = {}
    paginator = boto_session.client('organizations').get_paginator('list_accounts')
    response_iterator = paginator.paginate()
    for response in response_iterator:
        for account in response.get('Accounts'):
            dict_accounts[account.get('Id')] = account
    return dict_accounts


# Returns list of permission set ARNs assigned to an AWS Account
def list_permission_sets_provisioned_to_account(boto_session, account_id, idc_arn):
    logger = logging.getLogger(list_permission_sets_provisioned_to_account.__name__)
    logger.info(f'Retrieving permission set assignments for account {account_id}')
    try:
        permission_set_list = []
        paginator = boto_session.client('sso-admin').get_paginator('list_permission_sets_provisioned_to_account')
        response_iterator = paginator.paginate(
            AccountId=str(account_id),
            InstanceArn=str(idc_arn)
        )
        for response in response_iterator:
            permission_set_list.extend(response.get('PermissionSets', []))
    except ClientError as e:
        raise e
    logger.info(f'Permission set assignment list: \n{pp.pformat(permission_set_list)}')
    return permission_set_list


# Returns list of user and group assignments for the AWS account ID + Permission Set combination, format as per
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/list_account_assignments.html
def list_account_assignments(boto_session, account_id, idc_arn, permission_set_arn):
    logger = logging.getLogger(list_account_assignments.__name__)
    logger.info(f'Retrieving assignments for account {account_id}, permission set {permission_set_arn}')
    try:
        account_assignments_list = []
        paginator = boto_session.client('sso-admin').get_paginator('list_account_assignments')
        response_iterator = paginator.paginate(
            AccountId=str(account_id),
            InstanceArn=str(idc_arn),
            PermissionSetArn=str(permission_set_arn)
        )
        for response in response_iterator:
            account_assignments_list.extend(response.get('AccountAssignments', []))
    except ClientError as e:
        raise e
    logger.info(f'User and Group assignment list: \n{pp.pformat(account_assignments_list)}')
    return account_assignments_list


# Returns tuple (dict[group_id], dict[group_name]), where each dictionary's value is structured as per:
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/identitystore/client/list_groups.html
def list_groups(boto_session, idc_id):
    logger = logging.getLogger(list_groups.__name__)
    logger.info(f'Retrieving Groups for Identity Store {idc_id}')
    try:
        groups_by_id, groups_by_name = {}, {}
        paginator = boto_session.client('identitystore').get_paginator('list_groups')
        response_iterator = paginator.paginate(IdentityStoreId=str(idc_id))
        for response in response_iterator:
            for group in response.get('Groups'):
                groups_by_id[group.get('GroupId', 'N/A')] = group
                groups_by_name[group.get('DisplayName', group.get('GroupId', 'N/A'))] = group
    except ClientError as e:
        raise e
    logger.info(f' Identity Store groups Dictionary: \n{pp.pformat(groups_by_id)}')
    return groups_by_id, groups_by_name


# Returns tuple (dict[user_id], dict[user_name]), where each dictionary's value is structured as per:
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/identitystore/client/list_users.html
def list_users(boto_session, idc_id):
    logger = logging.getLogger(list_users.__name__)
    logger.info(f'Retrieving Users for Identity Store {idc_id}')
    try:
        users_by_id, users_by_name = {}, {}
        paginator = boto_session.client('identitystore').get_paginator('list_users')
        response_iterator = paginator.paginate(IdentityStoreId=str(idc_id))
        for response in response_iterator:
            for user in response.get('Users', []):
                users_by_id[user.get('UserId', 'N/A')] = user
                users_by_name[user.get('UserName', user.get('UserId', 'N/A'))] = user
    except ClientError as e:
        raise e
    logger.info(f' Identity Store users Dictionary: \n{pp.pformat(users_by_id)}')
    return users_by_id, users_by_name


# Creates a CSV file with the current IDC account > permissions set assignments to users and groups.
def list_assignments_to_csv(boto_session, idc_arn, accounts, permission_sets_by_arn,
                            users_by_id, groups_by_id, csv_file):
    logger = logging.getLogger(list_assignments_to_csv.__name__)
    logger.info(f'Generating CSV {csv_file} with IDC Account to Permission Set user and group assignments')
    with open(csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['account_id', 'permission_set', 'principal_name', 'user_or_group']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for account_id in accounts.keys():
            logger.info(f'  Listing for account {account_id}')
            perm_set_list = list_permission_sets_provisioned_to_account(boto_session, account_id, idc_arn)
            for perm_set_arn in perm_set_list:
                account_assignments = list_account_assignments(boto_session, account_id, idc_arn, perm_set_arn)
                for assignment in account_assignments:

                    # Stepping through to catch data errors on the responses.
                    permission_set_arn = assignment.get('PermissionSetArn', None)
                    if permission_set_arn is None:
                        logger.error(f'No "PermissionSetArn" on assignment {pp.pformat(assignment)}')
                        continue
                    permission_set = permission_sets_by_arn.get(permission_set_arn, None)
                    if permission_set is None:
                        logger.error(f'Cannot find {permission_set_arn} on Permission Set list')
                        continue
                    permission_set_name = permission_set.get('Name')

                    principal_id = assignment.get('PrincipalId', None)
                    if principal_id is None:
                        logger.error(f'No "PrincipalId" on assignment {pp.pformat(assignment)}')
                        continue
                    principal_type = assignment.get('PrincipalType', None)
                    if principal_type is None:
                        logger.error(f'No "PrincipalType" on assignment {pp.pformat(assignment)}')
                        continue
                    if principal_type == 'USER':
                        principal = users_by_id.get(principal_id, None)
                        if principal is None:
                            logger.error(f'Cannot find {principal_id} on users_by_id list')
                            continue
                        principal_name = principal.get('UserName', 'N/A')
                    elif principal_type == 'GROUP':
                        principal = groups_by_id.get(principal_id, None)
                        if principal is None:
                            logger.error(f'Cannot find {principal_id} on groups_by_id list')
                            continue
                        principal_name = principal.get('DisplayName', 'N/A')
                    else:
                        logger.error(f'Invalid "PrincipalType" value  {principal_type}')
                        continue
                    writer.writerow({'account_id': assignment.get('AccountId'),
                                     'permission_set': permission_set_name,
                                     'principal_name': principal_name,
                                     'user_or_group': principal_type})
    logger.info(f'Finished writing to {csv_file}')


# API call to assign permissions set + user/group to AWS Account. Returns request ID.
def create_account_assignment(boto_session, idc_arn, account_id, perm_set_arn, principal_id, principal_type):
    logger = logging.getLogger(create_account_assignment.__name__)
    logger.info(f'Assigning {principal_type} to Permissions set {perm_set_arn} on AWS account {account_id}')
    response = boto_session.client('sso-admin').create_account_assignment(
        InstanceArn=str(idc_arn),
        PermissionSetArn=str(perm_set_arn),
        PrincipalId=str(principal_id),
        PrincipalType=str(principal_type),
        TargetId=str(account_id),
        TargetType='AWS_ACCOUNT'
    )
    logger.info(f'   Response: \n{pp.pformat(response)}')
    request_id = ''
    if 'AccountAssignmentCreationStatus' in response:
        request_id = response.get('AccountAssignmentCreationStatus').get('RequestId', '')
    return request_id


# API call to check assignment status
def describe_account_assignment_creation_status(boto_session, idc_arn, assignment_id):
    logger = logging.getLogger(describe_account_assignment_creation_status.__name__)
    logger.info(f'Checking assignment request ID {assignment_id}')
    response = boto_session.client('sso-admin').describe_account_assignment_creation_status(
        AccountAssignmentCreationRequestId=str(assignment_id),
        InstanceArn=str(idc_arn)
    )
    logger.info(f'   Response: \n{pp.pformat(response)}')
    request_status, failure_reason = 'could not retrieve', ''
    if 'AccountAssignmentCreationStatus' in response:
        request_status = response.get('AccountAssignmentCreationStatus').get('Status', 'could not retrieve')
        failure_reason = response.get('AccountAssignmentCreationStatus').get('FailureReason', '')
    return request_status, failure_reason


# Check request status in a loop.
# issued_request_ids: dict['RequestID'] = 'Text to display'
def check_assignment_requests(boto_session, idc_arn, issued_request_ids):
    logger = logging.getLogger(check_assignment_requests.__name__)
    wait_time = 5 # Time between status checks
    logger.info(f'Checking assignment requests every {wait_time} seconds')
    review, next_review = issued_request_ids.keys(), []
    while len(review) != 0:
        msg = f'Waiting {wait_time} seconds'
        logger.info(msg)
        print(msg)
        time.sleep(wait_time) # Pause between status checks.
        next_review = []
        for ID in review:
            request_status, failure_reason = describe_account_assignment_creation_status(boto_session, idc_arn, ID)
            msg = f' Request {issued_request_ids[ID]}, status: {request_status} {failure_reason}'
            print(msg)
            logger.info(msg)
            if request_status != 'SUCCEEDED' and request_status != 'FAILED':
                next_review.append(ID)
        review = next_review
    logger.info(f'All assignments completed successfully')


# Reads a CSV file with the desired IDC account > permissions set assignments to users and groups.
# CSV headers:
# account_id,permission_set,principal_name,user_or_group
def perform_assignments_from_csv(boto_session, idc_arn, users_by_name, groups_by_name,
                                 permission_sets_by_name, csv_file, check_requests):
    logger = logging.getLogger(perform_assignments_from_csv.__name__)
    logger.info(f'Reading CSV {csv_file} and issuing IDC Account to Permission Set user and group assignments')

    issued_request_ids = {}
    with open(csv_file, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            for row in reader:
                if len(row) != 4:
                    raise ValueError
                account_id, permission_set_name = str(row[0]).strip(), str(row[1]).strip()
                principal_name, user_or_group = str(row[2]).strip(), str(row[3]).strip().upper()

                if (account_id == 'account_id' and permission_set_name == 'permission_set'
                        and principal_name == 'principal_name' and user_or_group == 'USER_OR_GROUP'):
                    logger.info(f'Skipping header row: {row}')
                    continue

                if (account_id == '' or permission_set_name == '' or principal_name == ''
                        or (user_or_group != 'USER' and user_or_group != 'GROUP')):
                    logger.error(f'Skipping invalid row: {row}')
                    continue

                if permission_set_name not in permission_sets_by_name:
                    logger.error(f'Not found: Permission set name {permission_set_name}')
                    continue
                permission_set_arn = permission_sets_by_name.get(permission_set_name).get('PermissionSetArn')

                principal_id = ''
                if user_or_group == 'USER':
                    if principal_name in users_by_name:
                        principal_id = users_by_name.get(principal_name).get('UserId', '')
                elif user_or_group == 'GROUP':
                    if principal_name in groups_by_name:
                        principal_id = groups_by_name.get(principal_name).get('GroupId', '')
                if principal_id == '':
                    logger.warning(f'Principal ID not found for {user_or_group} named {principal_name}')
                    continue

                logger.info(f'Issuing assignment request for {row}')
                request_id = create_account_assignment(boto_session,
                                                       idc_arn,
                                                       account_id,
                                                       permission_set_arn,
                                                       principal_id,
                                                       user_or_group)
                issued_request_ids[request_id] = row
        except csv.Error as e:
            sys.exit('file {}, line {}: {}'.format(csv_file, reader.line_num, e))
    logger.info(f'Request IDs to check status of asynchronous assignment requests {issued_request_ids.keys()}')
    if check_requests:
        check_assignment_requests(boto_session, idc_arn, issued_request_ids)


# Writes all principals to the file name passed as parameter.
def report_principals(users_by_id, groups_by_id, csv_file):
    logger = logging.getLogger(report_principals.__name__)
    logger.info(f'Writing AWS IDC principal report to {csv_file}')
    with open(csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['user_or_group', 'principal_name', 'principal_id', 'identity_store_id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        logger.info('  Writing users from Identity Store')
        for user in users_by_id.keys():
            writer.writerow({'user_or_group': 'USER',
                             'principal_name': users_by_id.get(user).get('UserName', ''),
                             'principal_id': users_by_id.get(user).get('UserId', ''),
                             'identity_store_id': users_by_id.get(user).get('IdentityStoreId', '')})
        logger.info('  Writing groups from Identity Store')
        for group in groups_by_id.keys():
            writer.writerow({'user_or_group': 'GROUP',
                             'principal_name': groups_by_id.get(group).get('DisplayName', ''),
                             'principal_id': groups_by_id.get(group).get('GroupId', ''),
                             'identity_store_id': groups_by_id.get(group).get('IdentityStoreId', '')})
    logger.info(f' Finished writing to {csv_file}')


def main(argv=None):
    clp = init_clp(argv)

    log_level = logging.INFO if clp.verbose else logging.ERROR
    debug_file = clp.debug if clp.debug != '' else None
    if debug_file is not None:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, filename=debug_file, filemode='w',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.debug('Starting process')

    session = boto3.Session(profile_name=clp.profile) if clp.profile != '' else boto3.Session()

    idc_arn, idc_id = get_idc_instance_information(session)
    users_by_id, users_by_name = list_users(session, idc_id)
    groups_by_id, groups_by_name = list_groups(session, idc_id)

    if clp.list:
        accounts = list_accounts(session)
        permission_sets_by_arn, _ = list_permission_sets(session, idc_arn)
        list_assignments_to_csv(session, idc_arn, accounts, permission_sets_by_arn,
                                users_by_id, groups_by_id, clp.output)
    if clp.principals:
        report_principals(users_by_id, groups_by_id, clp.output)
    if clp.set:
        _, permission_sets_by_name = list_permission_sets(session, idc_arn)
        perform_assignments_from_csv(session, idc_arn, users_by_name, groups_by_name,
                                     permission_sets_by_name, clp.input, clp.check)


if __name__ == '__main__':
    main(sys.argv[1:])
