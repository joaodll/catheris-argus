"""The versioned list of Steampipe AWS tables collected for the inventory (ADR-0012, amended
2026-10-08), and the options some of them are exported with."""

import re
from functools import cache
from importlib import resources


@cache
def steampipe_tables() -> tuple[str, ...]:
    text = (resources.files("argus.collection") / "steampipe_tables_aws.txt").read_text()
    return tuple(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


def _select(columns: str) -> tuple[str, ...]:
    """--select these columns only: the pinned plugin's columns of the table minus the ones
    left out. A column that is not selected is never hydrated, so its API call is not made."""
    return ("--select", ",".join(columns.split()))


_REGIONAL = "partition region account_id"
# Per table: extra arguments for steampipe_export_aws (plugin 1.34.0). Each one keeps a
# value Argus must not hold, a call the scanner role denies (ADR-0018), or a call that fails
# on resources the account does not own (ADR-0012, 2026-10-21) out of the export: one failing
# column would make the pinned plugin drop the whole table on every run.
TABLE_OPTIONS: dict[str, tuple[str, ...]] = {
    # AWS-managed policies have one global ARN shared by every account and ~1,300 rows: not
    # inventoried. Edges still point to their ARN (an edge endpoint may have no resource row).
    "aws_iam_policy": ("--where", "is_aws_managed = false"),
    # code, tags and reserved concurrency come from lambda:GetFunction (denied: function code).
    "aws_lambda_function": _select(
        f"""name arn code_sha_256 code_size dead_letter_config_target_arn description handler
        kms_key_arn last_modified timeout version package_type master_arn memory_size
        revision_id role runtime state state_reason state_reason_code last_update_status
        last_update_status_reason last_update_status_reason_code vpc_id architectures
        environment_variables file_system_configs ephemeral_storage policy policy_std
        tracing_config snap_start url_config logging_config vpc_security_group_ids
        vpc_subnet_ids title akas layers {_REGIONAL}"""
    ),
    "aws_lambda_version": _select(
        f"""function_name version arn package_type signing_job_arn target_arn kms_key_arn
        master_arn state code_sha_256 code_size description handler last_modified
        last_update_status last_update_status_reason last_update_status_reason_code
        memory_size revision_id runtime timeout vpc_id role signing_profile_version_arn
        state_reason state_reason_code ephemeral_storage_size environment_variables
        runtime_version_config environment_error logging_config policy policy_std
        vpc_security_group_ids vpc_subnet_ids architectures dead_letter_config
        file_system_configs image_config_response layers snap_start tracing_config title
        akas {_REGIONAL}"""
    ),
    # content and layer_arn come from lambda:GetLayerVersion (denied: layer code).
    "aws_lambda_layer_version": _select(
        f"""layer_name layer_version_arn created_date description license_info revision_id
        version compatible_architectures compatible_runtimes policy policy_std title akas
        {_REGIONAL}"""
    ),
    # launch_template_data comes from ec2:GetLaunchTemplateData, which the scanner role does not
    # grant: one denied call aborts the whole table, so no instance would be inventoried. It
    # and user_data carry the instance's user data (secrets in scripts): neither is exported.
    "aws_ec2_instance": _select(
        f"""instance_id arn instance_type instance_state monitoring_state
        disable_api_termination ami_launch_index architecture boot_mode
        current_instance_boot_mode ipv6_address capacity_reservation_id
        capacity_reservation_specification client_token cpu_options_core_count
        cpu_options_threads_per_core ebs_optimized ena_support hypervisor
        iam_instance_profile_arn iam_instance_profile_id image_id
        instance_initiated_shutdown_behavior instance_lifecycle kernel_id key_name launch_time
        outpost_arn placement_affinity placement_availability_zone placement_group_id
        placement_group_name placement_host_id placement_host_resource_group_arn
        placement_partition_number placement_tenancy platform platform_details
        private_ip_address private_dns_name public_dns_name public_ip_address ram_disk_id
        root_device_name root_device_type source_dest_check spot_instance_request_id
        sriov_net_support state_code state_transition_reason state_transition_time subnet_id
        tpm_support usage_operation usage_operation_update_time virtualization_type vpc_id
        block_device_mappings elastic_gpu_associations
        elastic_inference_accelerator_associations enclave_options hibernation_options
        state_reason licenses maintenance_options metadata_options network_interfaces
        private_dns_name_options product_codes security_groups instance_status tags_src title
        tags akas {_REGIONAL}"""
    ),
    # A template can hold default values of secret parameters; parameters and outputs stay
    # (redacted by name, NoEcho ones come back masked). Stacks and stack sets alike.
    "aws_cloudformation_stack": _select(
        f"""id name status stack_status_reason change_set_id detailed_status creation_time
        deletion_time retain_except_on_create disable_rollback enable_termination_protection
        last_updated_time parent_id role_arn root_id description timeout_in_minutes
        notification_arns outputs rollback_configuration capabilities stack_drift_status
        parameters resources tags_src tags title akas {_REGIONAL}"""
    ),
    "aws_cloudformation_stack_set": _select(
        f"""stack_set_id stack_set_name arn status description drift_status
        last_drift_check_timestamp permission_model administration_role_arn execution_role_name
        auto_deployment capabilities organizational_unit_ids parameters
        stack_set_drift_detection_details managed_execution tags_src tags title akas
        {_REGIONAL}"""
    ),
    # DescribeVpcEndpointServicePermissions on the AWS-owned services the table also lists:
    # refused by their resource policy.
    "aws_vpc_endpoint_service": _select(
        f"""service_name service_id owner acceptance_required manages_vpc_endpoints
        private_dns_name private_dns_name_verification_state vpc_endpoint_policy_supported
        availability_zones base_endpoint_dns_names service_type vpc_endpoint_connections
        tags_src tags title akas {_REGIONAL}"""
    ),
    # ListTagsForResource on AWS-owned public images: refused.
    "aws_appstream_image": _select(
        f"""name arn appstream_agent_version base_image_arn created_time description
        display_name image_builder_name image_builder_supported platform
        public_base_image_released_date state visibility applications image_errors
        image_permissions state_change_reason title akas {_REGIONAL}"""
    ),
    # ListResourceTags on a key whose key policy does not hand access to IAM: refused, and
    # every other key of the account would be lost with it.
    "aws_kms_key": _select(
        f"""id arn key_manager creation_date aws_account_id enabled customer_master_key_spec
        description deletion_date key_state key_usage origin valid_to aliases
        key_rotation_enabled policy policy_std multi_region multi_region_configuration title
        akas {_REGIONAL}"""
    ),
    # GetLoggingConfiguration answers WAFNonexistentItemException for every ACL without
    # logging. Prowler's checks report WAF logging.
    "aws_wafv2_web_acl": _select(
        f"""name arn id scope description capacity lock_token managed_by_firewall_manager
        custom_response_bodies label_namespace retrofitted_by_firewall_manager token_domains
        associated_resources default_action pre_process_firewall_manager_rule_groups
        post_process_firewall_manager_rule_groups rules visibility_config tags_src title tags
        akas {_REGIONAL}"""
    ),
}


def table_options(table: str) -> tuple[str, ...]:
    return TABLE_OPTIONS.get(table, ())


# The Inspector collector (ADR-0042): two tables of the same plugin, exported by the same binary
# in their own run. Not on the Steampipe list: they are another tool's findings, not
# configuration.
INSPECTOR_FINDINGS = "aws_inspector2_finding"
INSPECTOR_COVERAGE = "aws_inspector2_coverage"
INSPECTOR_TABLES = (INSPECTOR_FINDINGS, INSPECTOR_COVERAGE)
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")


def inspector_table_options(table: str, account_id: str) -> tuple[str, ...]:
    """Only this account's open findings: `finding_account_id` and `status` are key columns,
    pushed down to ListFindings' filter, so a delegated administrator's connection never
    exports its member accounts' findings. Closed findings are left out: a complete run
    resolves what it no longer reports. Coverage is filtered by account in the adapter (its
    account column is not a documented key column). Only the columns the adapter reads."""
    if not _ACCOUNT_ID.match(account_id):
        raise ValueError("an account id is 12 digits")
    if table == INSPECTOR_FINDINGS:
        return (
            "--where",
            f"finding_account_id = '{account_id}'",
            "--where",
            "status <> 'CLOSED'",
            *_select(
                f"""arn finding_account_id status type severity title description
                vulnerability_id exploit_available fix_available inspector_score epss_score
                vulnerable_packages cvss remediation_recommendation_text
                remediation_recommendation_url source_url resources first_observed_at
                last_observed_at updated_at {_REGIONAL}"""
            ),
        )
    if table == INSPECTOR_COVERAGE:
        return _select(
            f"""resource_id resource_type scan_type scan_status_code scan_status_reason
            last_scanned_at source_account_id ecr_repository_name {_REGIONAL}"""
        )
    raise ValueError(f"not an Inspector table: {table}")
