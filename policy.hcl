policy "cis-v1.20" {
  description = "AWS CIS V1.20 Policy"
  configuration {
    provider "aws" {
      version = ">= 0.5.0"
    }
  }

  view "aws_log_metric_filter_and_alarm" {
    description = "AWS Log Metric Filter and Alarm"
    query "aws_log_metric_filter_and_alarm_query" {
      query = file("queries/aws-log-view.sql")
    }
  }

  policy "aws-cis-section-1" {
    description = "AWS CIS Section 1"

    query "1.1" {
      description = "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days"
      query       = <<EOF
      SELECT account_id, password_last_used, user_name FROM aws_iam_users
      WHERE user_name = '<root_account>' AND password_last_used > (now() - '30 days'::interval)
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The root account has unrestricted access to all resources in the AWS account. We highly recommend that you avoid using this account. The root account is the most privileged account. Minimizing the use of this account and adopting the principle of least privilege for access management reduces the risk of accidental changes and unintended disclosure of highly privileged credentials.
    EOF
        description     = <<EOF
The root account has unrestricted access to all resources in the AWS account. We highly recommend that you avoid using this account. The root account is the most privileged account. Minimizing the use of this account and adopting the principle of least privilege for access management reduces the risk of accidental changes and unintended disclosure of highly privileged credentials.

As a best practice, use your root credentials only when required to perform account and service management tasks. Apply IAM policies directly to groups and roles but not users. Affected assets include root accounts used in last 30 days
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. See https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-standards-cis-controls-1.1 for more information.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-standards-cis-controls-1.1
    EOF
        source          = "mage"
      }

    }

    query "1.2" {
      description = "AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password"
      query       = <<EOF
      SELECT account_id, password_last_used, user_name, mfa_active FROM aws_iam_users
      WHERE password_enabled AND NOT mfa_active
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Multi-factor authentication (MFA) adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password as well as for an authentication code from their AWS MFA device.
    EOF
        description     = <<EOF
Multi-factor authentication (MFA) adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password as well as for an authentication code from their AWS MFA device.

Security Hub recommends enabling MFA for all accounts that have a console password. Enabling MFA provides increased security for console access because it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.
    EOF
        recommendations = <<EOF
The steps to remediate this issue including configuring MFA for the affected user(s). See https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.2 for more information.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.2
    EOF
        source          = "mage"
      }
    }

    query "1.3" {
      description = "AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled"
      query       = <<EOF
      SELECT account_id, arn, password_last_used, user_name, access_key_id, last_used FROM aws_iam_users
        JOIN aws_iam_user_access_keys on aws_iam_users.cq_id = aws_iam_user_access_keys.user_cq_id
       WHERE (password_enabled AND password_last_used < (now() - '90 days'::interval) OR
             (last_used < (now() - '90 days'::interval)))
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended to remove or deactivate all credentials that have been used in 90 days or more.
    EOF
        description     = <<EOF
IAM users can access AWS resources using different types of credentials, such as passwords or access keys.

Security Hub recommends that you remove or deactivate all credentials that have been unused in 90 days or more. Disabling or removing unnecessary credentials reduces the window of opportunity for credentials associated with a compromised
or abandoned account to be used.
    EOF
        recommendations = <<EOF
You can use the IAM console, along with credential reports, to monitor accounts for dated credentials. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-co
ntrols-1.3.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.3
    EOF
        source          = "mage"
      }
    }

    query "1.4" {
      description = "AWS CIS 1.4 Ensure access keys are rotated every 90 days or less"
      query       = <<EOF
      SELECT account_id, arn, password_last_used, user_name, access_key_id, last_used, last_rotated FROM aws_iam_users
        JOIN aws_iam_user_access_keys on aws_iam_users.cq_id = aws_iam_user_access_keys.user_cq_id
       WHERE last_rotated < (now() - '90 days'::interval)
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interfa
ce (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services.

Security Hub recommends that you regularly rotate all access keys.
    EOF
        description     = <<EOF
Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interfa
ce (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services.

Security Hub recommends that you regularly rotate all access keys. Rotating access keys reduces the chance for an access key that is associated with a compromised or terminated account to be used. Rotate access keys to ensure that data ca
n't be accessed with an old key that might have been lost, cracked, or stolen.
    EOF
        recommendations = <<EOF
You can use the IAM console, along with credential reports, to monitor accounts for dated credentials. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-co
ntrols-1.4.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.4
    EOF
        source          = "mage"
      }
    }

    query "1.5" {
      description = "AWS CIS 1.5  Ensure IAM password policy requires at least one uppercase letter"
      query       = <<EOF
      SELECT account_id, require_uppercase_characters FROM aws_iam_password_policies
       WHERE require_uppercase_characters = FALSE
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one uppercase letter.
    EOF
        description     = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one uppercase letter. Setting a password complexity policy increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.5.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.5
    EOF
        source          = "mage"
      }
    }

    query "1.6" {
      description = "AWS CIS 1.6  Ensure IAM password policy requires at least one lowercase letter"
      query       = <<EOF
      SELECT account_id, require_lowercase_characters FROM aws_iam_password_policies
       WHERE require_lowercase_characters = FALSE
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one lowercase letter.
    EOF
        description     = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one lowercase letter. Setting a password complexity policy increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.6.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.6
    EOF
        source          = "mage"
      }
    }

    query "1.7" {
      description = "AWS CIS 1.7  Ensure IAM password policy requires at least one symbol"
      query       = <<EOF
      SELECT account_id, require_symbols FROM aws_iam_password_policies
       WHERE require_symbols = FALSE
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one symbol.
    EOF
        description     = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one symbol. Setting a password complexity policy increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.7.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.7
    EOF
        source          = "mage"
      }
    }

    query "1.8" {
      description = "AWS CIS 1.8  Ensure IAM password policy requires at least one number"
      query       = <<EOF
      SELECT account_id, require_numbers FROM aws_iam_password_policies
       WHERE require_numbers = FALSE
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one number.
    EOF
        description     = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require at least one number. Setting a password complexity policy increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.8.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.8
    EOF
        source          = "mage"
      }
    }

    query "1.9" {
      description = "AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater"
      query       = <<EOF
      SELECT account_id, minimum_password_length FROM aws_iam_password_policies
       WHERE minimum_password_length < 14
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords are at least a given length.

Security Hub recommends that the password policy require at least one number.
    EOF
        description     = <<EOF
Password policies, in part, enforce password complexity requirements. Use IAM password policies to ensure that passwords use different character sets.

Security Hub recommends that the password policy require a minimum password length of 14 characters. Setting a password complexity policy increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.9.
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.9
    EOF
        source          = "mage"
      }
    }

    query "1.10" {
      description = "AWS CIS 1.10 Ensure IAM password policy prevents password reuse"
      query       = <<EOF
      SELECT account_id, password_reuse_prevention FROM aws_iam_password_policies
       WHERE password_reuse_prevention is NULL or password_reuse_prevention > 24
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
IAM password policies can prevent the reuse of a given password by the same user. This control checks whether the number of passwords to remember is set to 24. The control fails if the value is not 24.
    EOF
        description     = <<EOF
IAM password policies can prevent the reuse of a given password by the same user. This control checks whether the number of passwords to remember is set to 24. The control fails if the value is not 24.

Security Hub recommends that the password policy prevent the reuse of passwords. Preventing password reuse increases account resiliency against brute force login attempts.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.10
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.10
    EOF
        source          = "mage"
      }
    }

    query "1.11" {
      description = "AWS CIS 1.11 Ensure IAM password policy expires passwords within 90 days or less"
      query       = <<EOF
      SELECT account_id, max_password_age FROM aws_iam_password_policies
       WHERE max_password_age is NULL or max_password_age < 90
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
IAM password policies can require passwords to be rotated or expired after a given number of days.

Security Hub recommends that the password policy expire passwords after 90 days or less. Reducing the password lifetime increases account resiliency against brute force login attempts.
    EOF
        description     = <<EOF
IAM password policies can require passwords to be rotated or expired after a given number of days.

Security Hub recommends that the password policy expire passwords after 90 days or less. Reducing the password lifetime increases account resiliency against brute force login attempts. Requiring regular password changes also helps in the
following scenarios:

- Passwords can be stolen or compromised without your knowledge. This can happen via a system compromise, software vulnerability, or internal threat.
- Certain corporate and government web filters or proxy servers can intercept and record traffic even if it's encrypted.
- Many people use the same password for many systems such as work, email, and personal.
- Compromised end-user workstations might have a keystroke logger.
    EOF
        recommendations = <<EOF
You can use the IAM console to modify the password policy. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.11
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.11
    EOF
        source          = "mage"
      }
    }

    query "1.12" {
      description = "AWS CIS 1.12  Ensure no root account access key exists"
      query       = <<EOF
      select * from aws_iam_users
          JOIN aws_iam_user_access_keys aiuak on aws_iam_users.cq_id = aiuak.user_cq_id
      WHERE user_name = '<root>'
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The root account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given account. It is recommended to remove access keys associated with the root account.
    EOF
        description     = <<EOF
The root account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given account. It is recommended to remove access keys associated with the root account.

Security Hub recommends that all access keys be associated with the root account be removed. Removing access keys associated with the root account limits vectors that the account can be compromised by. Removing the root access keys also e
ncourages the creation and use of role-based accounts that are least privileged.
    EOF
        recommendations = <<EOF
You can use the IAM console to remove access keys. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.12
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.12
    EOF
        source          = "mage"
      }
    }

    query "1.13" {
      description = "AWS CIS 1.13 Ensure MFA is enabled for the 'root' account"
      query       = <<EOF
      SELECT account_id, arn, password_last_used, user_name, mfa_active FROM aws_iam_users
      WHERE user_name = '<root_account>' AND NOT mfa_active
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The root account is the most privileged user in an account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and p
assword and for an authentication code from their AWS MFA device.
    EOF
        description     = <<EOF
The root account is the most privileged user in an account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and p
assword and for an authentication code from their AWS MFA device.

When you use virtual MFA for root accounts, Security Hub recommends that the device used is not a personal device. Instead, use a dedicated mobile device (tablet or phone) that you manage to keep charged and secured independent of any ind
ividual personal devices. This lessens the risks of losing access to the MFA due to device loss, device trade-in, or if the individual owning the device is no longer employed at the company.
    EOF
        recommendations = <<EOF
You can use the IAM console to enable MFA for the root account. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.13
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.13
    EOF
        source          = "mage"
      }
    }

    query "1.14" {
      description   = "AWS CIS 1.14 Ensure hardware MFA is enabled for the 'root' account"
      expect_output = true
      query         = <<EOF
      SELECT aiu.account_id, arn, password_last_used, aiu.user_name, mfa_active FROM aws_iam_users as aiu
      JOIN aws_iam_virtual_mfa_devices ON aws_iam_virtual_mfa_devices.user_arn = aiu.arn
      WHERE aiu.user_name = '<root_account>' AND aiu.mfa_active
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The root account is the most privileged user in an account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and p
assword and for an authentication code from their AWS MFA device.
    EOF
        description     = <<EOF
The root account is the most privileged user in an account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and p
assword and for an authentication code from their AWS MFA device.

For Level 2, Security Hub recommends that you protect the root account with a hardware MFA. A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA doesn't suffer the attack surface introduced by the mo
bile smartphone that a virtual MFA resides on. Using hardware MFA for many, many accounts might create a logistical device management issue. If this occurs, consider implementing this Level 2 recommendation selectively to the highest secu
rity accounts. You can then apply the Level 1 recommendation to the remaining accounts.
    EOF
        recommendations = <<EOF
You can use the IAM console to enable MFA for the root account. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.14
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.14
    EOF
        source          = "mage"
      }
    }

    query "1.16" {
      description = "AWS CIS 1.16 Ensure IAM policies are attached only to groups or roles"
      query       = <<EOF
      SELECT aws_iam_users.account_id, arn, user_name FROM aws_iam_users
      JOIN aws_iam_user_attached_policies aiuap on aws_iam_users.cq_id = aiuap.user_cq_id
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are how privileges are granted to users, groups, or roles. It is recommended that IAM policies are attached to groups and roles, but not users.
    EOF
        description     = <<EOF
By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are how privileges are granted to users, groups, or roles.

Security Hub recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access manag
ement complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.
    EOF
        recommendations = <<EOF
You can use the IAM console to create groups and roles. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.16
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.16
    EOF
        source          = "mage"
      }
    }
  }

  policy "aws-cis-section-2" {
    description = "AWS CIS Section 2"

    query "2.1" {
      description = "AWS CIS 2.1 Ensure CloudTrail is enabled in all regions"
      query       = <<EOF
      SELECT aws_cloudtrail_trails.account_id, arn, is_multi_region_trail, read_write_type, include_management_events FROM aws_cloudtrail_trails
      JOIN aws_cloudtrail_trail_event_selectors on aws_cloudtrail_trails.cq_id = aws_cloudtrail_trail_event_selectors.trail_cq_id
      WHERE is_multi_region_trail = FALSE OR (is_multi_region_trail = TRUE AND (read_write_type != 'All' OR include_management_events = FALSE))
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
CloudTrail is a service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, th
e request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the AWS Management Console, AWS SDKs, command-line tools, and higher-
level AWS services (such as AWS CloudFormation). It is recommended that Cloudtrail be enabled in all regions.
    EOF
        description     = <<EOF
CloudTrail is a service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, th
e request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the AWS Management Console, AWS SDKs, command-line tools, and higher-
level AWS services (such as AWS CloudFormation).

The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally:
- Ensuring that a multi-Region trail exists ensures that unexpected activity occurring in otherwise unused Regions is detected
- Ensuring that a multi-Region trail exists ensures that Global Service Logging is enabled for a trail by default to capture recording of events generated on AWS global services
- For a multi-Region trail, ensuring that management events configured for all type of Read/Writes ensures recording of management operations that are performed on all resources in an AWS account

By default, CloudTrail trails that are created using the AWS Management Console are multi-Region trails.
    EOF
        recommendations = <<EOF
You can use the Cloudtrail console to create and enable Trails. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.1
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.1
    EOF
        source          = "mage"
      }
    }

    query "2.2" {
      description = "AWS CIS 2.2 Ensure CloudTrail log file validation is enabled"
      query       = <<EOF
      SELECT aws_cloudtrail_trails.account_id, region, arn, log_file_validation_enabled FROM aws_cloudtrail_trails
      WHERE log_file_validation_enabled = FALSE
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. You can use these digest files to determine whether a log file was changed, deleted, or unchanged after
CloudTrail delivered the log.
    EOF
        description     = <<EOF
CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. You can use these digest files to determine whether a log file was changed, deleted, or unchanged after
CloudTrail delivered the log.

Security Hub recommends that you enable file validation on all trails. Enabling log file validation provides additional integrity checking of CloudTrail logs.
    EOF
        recommendations = <<EOF
You can use the Cloudtrail console to enable CloudTrail log file validation. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.2
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.2
    EOF
        source          = "mage"
      }
    }

    query "2.4" {
      description = "AWS CIS 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs"
      query       = <<EOF
      SELECT aws_cloudtrail_trails.account_id, arn, latest_cloud_watch_logs_delivery_time from aws_cloudtrail_trails
      WHERE cloud_watch_logs_log_group_arn is NULL OR latest_cloud_watch_logs_delivery_time < (now() - '1 days'::interval)
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameter
s, and the response elements returned by the AWS service. It is recommended to configure CloudTrail to send logs to CloudWatch for real-time analysis.
    EOF
        description     = <<EOF
CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameter
s, and the response elements returned by the AWS service.

CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs in a specified Amazon S3 bucket for long-term analysis, you can perform real-time analysis by configuri
ng CloudTrail to send logs to CloudWatch Logs.

For a trail that is enabled in all Regions in an account, CloudTrail sends log files from all those Regions to a CloudWatch Logs log group.

Security Hub recommends that you send CloudTrail logs to CloudWatch Logs.
    EOF
        recommendations = <<EOF
You can use the Cloudtrail console to integrate logs with CloudWatch. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.4
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.4
    EOF
        source          = "mage"
      }
    }

    query "2.6" {
      description = "AWS CIS 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
      query       = <<EOF
      SELECT aws_cloudtrail_trails.account_id, s3_bucket_name, aws_cloudtrail_trails.arn from aws_cloudtrail_trails
      JOIN aws_s3_buckets on s3_bucket_name = aws_s3_buckets.name
      WHERE logging_target_bucket is NULL OR logging_target_prefix is NULL
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Amazon S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the re
quest worked, and the time and date the request was processed. It is recommended that you enable bucket access logging on the CloudTrail S3 bucket.
    EOF
        description     = <<EOF
Amazon S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the re
quest worked, and the time and date the request was processed.

Security Hub recommends that you enable bucket access logging on the CloudTrail S3 bucket.

By enabling S3 bucket logging on target S3 buckets, you can capture all events that might affect objects in a target bucket. Configuring logs to be placed in a separate bucket enables access to log information, which can be useful in secu
rity and incident response workflows.
    EOF
        recommendations = <<EOF
You can use the S3 console to enable S3 bucket access logging. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.6
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.6
    EOF
        source          = "mage"
      }
    }

    query "2.7" {
      description = "AWS CIS 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
      query       = <<EOF
      SELECT account_id, region, arn, kms_key_id from aws_cloudtrail_trails
      WHERE kms_key_id is NULL
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
AWS Key Management Service (AWS KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses hardware security modules (HSMs) to protect the security of encryption keys.

You can configure CloudTrail logs to leverage server-side encryption (SSE) and AWS KMS customer-created master keys (CMKs) to further protect CloudTrail logs.
    EOF
        description     = <<EOF
CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (AWS KMS) is a managed service that helps create a
nd control the encryption keys used to encrypt account data, and uses hardware security modules (HSMs) to protect the security of encryption keys.

You can configure CloudTrail logs to leverage server-side encryption (SSE) and AWS KMS customer-created master keys (CMKs) to further protect CloudTrail logs.

Security Hub recommends that you configure CloudTrail to use SSE-KMS.

Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data because a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.
    EOF
        recommendations = <<EOF
You can use the CloudTrail console to enable encryption for CloudTrail logs. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.7
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.7
    EOF
        source          = "mage"
      }
    }

    query "2.8" {
      description = "AWS CIS 2.8 Ensure rotation for customer created CMKs is enabled"
      query       = <<EOF
      SELECT account_id, region, arn FROM aws_kms_keys WHERE rotation_enabled = FALSE AND manager = 'CUSTOMER'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
AWS KMS enables customers to rotate the backing key, which is key material stored in AWS KMS and is tied to the key ID of the CMK. It is recommended that you enable CMK key rotation.
    EOF
        description     = <<EOF
AWS KMS enables customers to rotate the backing key, which is key material stored in AWS KMS and is tied to the key ID of the CMK. It's the backing key that is used to perform cryptographic operations such as encryption and decryption
. Automated key rotation currently retains all previous backing keys so that decryption of encrypted data can take place transparently.

Security Hub recommends that you enable CMK key rotation. Rotating encryption keys helps reduce the potential impact of a compromised key because data encrypted with a new key can't be accessed with a previous key that might have been exp
osed.
    EOF
        recommendations = <<EOF
You can use the KMS console to enable CMK rotation. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.8
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.8
    EOF
        source          = "mage"
      }
    }

    query "2.9" {
      description = "AWS CIS 2.9 Ensure VPC flow logging is enabled in all VPCs"
      query       = <<EOF
      SELECT aws_ec2_vpcs.account_id, aws_ec2_vpcs.region, aws_ec2_vpcs.id FROM aws_ec2_vpcs
      LEFT JOIN aws_ec2_flow_logs ON aws_ec2_vpcs.id = aws_ec2_flow_logs.resource_id WHERE aws_ec2_flow_logs.resource_id is NULL
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
VPC flow logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you have created a flow log, you can view and retrieve its data in CloudWatch Logs.
    EOF
        description     = <<EOF
VPC flow logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you have created a flow log, you can view and retrieve its data in CloudWatch Logs.

Security Hub recommends that you enable flow logging for packet rejects for VPCs. Flow logs provide visibility into network traffic that traverses the VPC and can detect anomalous traffic or insight during security workflows.
    EOF
        recommendations = <<EOF
You can use the VPC console to enable VPC flow logging. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.9
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.9
    EOF
        source          = "mage"
      }
    }
  }

  policy "aws-cis-section-3" {
    description = "AWS CIS Section 3"

    query "3.1" {
      description   = "AWS CIS 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metrics filter and alarm for unauthorized API calls.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm unauthorized API calls. Monitoring unauthorized API calls helps reveal application errors and might reduce time to detect malicious activity.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.1
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.1
    EOF
        source          = "mage"
      }
    }

    query "3.2" {
      description   = "AWS CIS 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.errorCode = "ConsoleLogin") || ($.additionalEventData.MFAUsed != "Yes")  }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm console logins that aren't pr
otected by MFA.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm console logins that aren't protected by MFA. Monitoring for single-factor console logins increases visibility into accounts that aren't protected by MFA.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.2
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.2
    EOF
        source          = "mage"
      }
    }

    query "3.3" {
      description   = "AWS CIS 3.3  Ensure a log metric filter and alarm exist for usage of 'root' account (Score)"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for root login attempts.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for root login attempts. Monitoring for root account logins provides visibility into the use of a fully privileged account and an opportunity to reduce the use of it.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.3
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.3
    EOF
        source          = "mage"
      }
    }

    query "3.4" {
      description   = "AWS CIS 3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Score)"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy)}'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for changes made to IAM polic
ies.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for changes made to IAM policies. Monitoring these changes helps ensure that authentication and authorization controls remain intact.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.4
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.4
    EOF
        source          = "mage"
      }
    }

    query "3.5" {
      description   = "AWS CIS 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for changes to CloudTrail con
figuration settings.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for changes to CloudTrail configuration settings. Monitoring these changes helps ensure sustained visibility to activities in the account.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.5
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.5
    EOF
        source          = "mage"
      }
    }

    query "3.6" {
      description   = "AWS CIS 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for failed console authentica
tion attempts.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for failed console authentication attempts. Monitoring failed console logins might decrease lead time to detect an attempt to brute-force a credential, which might provide
an indicator, such as source IP, that you can use in other event correlations.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.6
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.6
    EOF
        source          = "mage"
      }
    }

    query "3.7" {
      description   = "AWS CIS 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for customer-created CMKs tha
t have changed state to disabled or scheduled deletion.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for customer-created CMKs that have changed state to disabled or scheduled deletion. Data encrypted with disabled or deleted keys is no longer accessible.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.7
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.7
    EOF
        source          = "mage"
      }
    }

    query "3.8" {
      description   = "AWS CIS 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for changes to S3 bucket poli
cies.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for changes to S3 bucket policies. Monitoring these changes might reduce time to detect and correct permissive policies on sensitive S3 buckets.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.8
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.8
    EOF
        source          = "mage"
      }
    }

    query "3.9" {
      description   = "AWS CIS 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended to create a metric filter and alarm for changes to AWS Config con
figuration settings.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.

Security Hub recommends that you create a metric filter and alarm for changes to AWS Config configuration settings. Monitoring these changes helps ensure sustained visibility of configuration items in the account.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.9
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.9
    EOF
        source          = "mage"
      }
    }

    query "3.10" {
      description   = "AWS CIS 3.10 Ensure a log metric filter and alarm exist for security group changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security groups are a stateful packet filter that controls ingress and egress traff
ic in a VPC. It is recommended that you create a metric filter and alarm for changes to security groups.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security groups are a stateful packet filter that controls ingress and egress traff
ic in a VPC.

Security Hub recommends that you create a metric filter and alarm for changes to security groups. Monitoring these changes helps ensure that resources and services aren't unintentionally exposed.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.10
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.10
    EOF
        source          = "mage"
      }
    }

    query "3.11" {
      description   = "AWS CIS 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic f
or subnets in a VPC. It is recommended that you create a metric filter and alarm for changes to NACLs.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic f
or subnets in a VPC.

Security Hub recommends that you create a metric filter and alarm for changes to NACLs. Monitoring these changes helps ensure that AWS resources and services aren't unintentionally exposed.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.11
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.11
    EOF
        source          = "mage"
      }
    }

    query "3.12" {
      description   = "AWS CIS 3.12 Ensure a log metric filter and alarm exist for changes to network gateways"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Network gateways are required to send and receive traffic to a destination outside
a VPC. It is recommended that you create a metric filter and alarm for changes to network gateways.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Network gateways are required to send and receive traffic to a destination outside
a VPC.

Security Hub recommends that you create a metric filter and alarm for changes to network gateways. Monitoring these changes helps ensure that all ingress and egress traffic traverses the VPC border via a controlled path.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.12
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.12
    EOF
        source          = "mage"
      }
    }

    query "3.13" {
      description   = "AWS CIS 3.13 Ensure a log metric filter and alarm exist for route table changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables route network traffic between subnets and to network gateways. It is
 recommended that you create a metric filter and alarm for changes to route tables.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables route network traffic between subnets and to network gateways.

Security Hub recommends that you create a metric filter and alarm for changes to route tables. Monitoring these changes helps ensure that all VPC traffic flows through an expected path.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.13
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.13
    EOF
        source          = "mage"
      }
    }

    query "3.14" {
      description   = "AWS CIS 3.14 Ensure a log metric filter and alarm exist for VPC changes"
      expect_output = true
      query         = <<EOF
      SELECT account_id, region, cloud_watch_logs_log_group_arn  FROM aws_log_metric_filter_and_alarm
      WHERE pattern='{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. You can have more than one VPC in an account, and you can create a peer connection
between two VPCs, enabling network traffic to route between VPCs. It is recommended that you create a metric filter and alarm for changes to VPCs.
    EOF
        description     = <<EOF
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. You can have more than one VPC in an account, and you can create a peer connection
between two VPCs, enabling network traffic to route between VPCs.

Security Hub recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.
    EOF
        recommendations = <<EOF
The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls
.html#securityhub-cis-controls-3.14
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.14
    EOF
        source          = "mage"
      }
    }
  }

  policy "aws-cis-section-4" {
    description = "AWS CIS Section 4"

    query "4.1" {
      description = "AWS CIS 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
      query       = <<EOF
      select account_id, region, group_name, from_port, to_port, cidr_ip from aws_ec2_security_groups
          JOIN aws_ec2_security_group_ip_permissions on aws_ec2_security_groups.cq_id = aws_ec2_security_group_ip_permissions.security_group_cq_id
          JOIN aws_ec2_security_group_ip_permission_ip_ranges on aws_ec2_security_group_ip_permissions.cq_id = aws_ec2_security_group_ip_permission_ip_ranges.security_group_ip_permission_cq_id
      WHERE from_port >= 0 AND to_port <= 22 AND cidr_ip = '0.0.0.0/0'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allow unrestricted ingress access to port 22.
    EOF
        description     = <<EOF
Security groups provide stateful filtering of ingress and egress network traffic to AWS resources.

Security Hub recommends that no security group allow unrestricted ingress access to port 22. Removing unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk.
    EOF
        recommendations = <<EOF
You can use the VPC console to edit inbound rules for security groups. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.1
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.1
    EOF
        source          = "mage"
      }
    }

    query "4.2" {
      description = "AWS CIS 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
      query       = <<EOF
      select account_id, region, group_name, from_port, to_port, cidr_ip from aws_ec2_security_groups
          JOIN aws_ec2_security_group_ip_permissions on aws_ec2_security_groups.cq_id = aws_ec2_security_group_ip_permissions.security_group_cq_id
          JOIN aws_ec2_security_group_ip_permission_ip_ranges on aws_ec2_security_group_ip_permissions.cq_id = aws_ec2_security_group_ip_permission_ip_ranges.security_group_ip_permission_cq_id
      WHERE from_port >= 0 AND to_port <= 3389 AND cidr_ip = '0.0.0.0/0'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allow unrestricted ingress access to port 3389.
    EOF
        description     = <<EOF
Security groups provide stateful filtering of ingress and egress network traffic to AWS resources.

Security Hub recommends that no security group allow unrestricted ingress access to port 3389. Removing unfettered connectivity to remote console services, such as RDP, reduces a server's exposure to risk.
    EOF
        recommendations = <<EOF
You can use the VPC console to edit inbound rules for security groups. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.2
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.2
    EOF
        source          = "mage"
      }
    }

    query "4.3" {
      description = "AWS CIS 4.3  Ensure the default security group of every VPC restricts all traffic"
      query       = <<EOF
      select account_id, region, group_name, from_port, to_port, cidr_ip from aws_ec2_security_groups
        JOIN aws_ec2_security_group_ip_permissions on aws_ec2_security_groups.cq_id = aws_ec2_security_group_ip_permissions.security_group_cq_id
        JOIN aws_ec2_security_group_ip_permission_ip_ranges on aws_ec2_security_group_ip_permissions.cq_id = aws_ec2_security_group_ip_permission_ip_ranges.security_group_ip_permission_cq_id
      WHERE group_name='default' AND cidr_ip = '0.0.0.0/0'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
A VPC comes with a default security group with initial settings that deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group w
hen you launch an instance, the instance is automatically assigned to this default security group.
    EOF
        description     = <<EOF
A VPC comes with a default security group with initial settings that deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group w
hen you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress and egress network traffic to AWS resources.

Security Hub recommends that the default security group restrict all traffic.
    EOF
        recommendations = <<EOF
You can use the VPC and EC2 consoles to edit security groups. For more information, see https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.3
    EOF
        references      = <<EOF
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.3
    EOF
        source          = "mage"
      }
    }
  }
}
