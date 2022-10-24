/*
req:
case 'Q'            simple query
case 'P'            parse
case 'B'            bind
case 'E'            execute
case 'F'            fastpath function call
case 'C'            close
case 'D'            describe
case 'H'            flush
case 'S'            sync
case 'X'            exit
case 'd'            copy data
case 'c'            copy done
case 'f'            copy fail

resp:
case 'C':        command complete
case 'E':        error return
case 'Z':        backend is ready for new query
case 'I':        empty query
case '1':        Parse Complete
case '2':        Bind Complete
case '3':        Close Complete
case 'S':        parameter status
case 'K':        secret key data from the backend
case 'T':        Row Description
case 'n':        No Data
case 'N':        No Data
case 't':        Parameter Description
case 'D':        Data Row
case 'G':        Start Copy In
case 'H':        Start Copy Out
case 'W':        Start Copy Both
case 'd':        Copy Data
case 'c':        Copy Done
case 'R':        Authentication Reques, should ignore
*/

use crate::flow_generator::protocol_logs::L7ResponseStatus;

const REQ_STR_Q: &'static str = "simple query";
const REQ_STR_P: &'static str = "parse";
const REQ_STR_B: &'static str = "bind";
const REQ_STR_E: &'static str = "execute";
const REQ_STR_F: &'static str = "fastpath function call";
const REQ_STR_C: &'static str = "close";
const REQ_STR_D: &'static str = "describe";
const REQ_STR_H: &'static str = "flush";
const REQ_STR_S: &'static str = "sync";
const REQ_STR_X: &'static str = "exit";
const REQ_STR_COPY_DATA: &'static str = "copy data";
const REQ_STR_COPY_DONE: &'static str = "copy done";
const REQ_STR_COPY_FAIL: &'static str = "copy fail";

pub(super) fn get_request_str(typ: char) -> &'static str {
    match typ {
        'Q' => REQ_STR_Q,
        'P' => REQ_STR_P,
        'B' => REQ_STR_B,
        'E' => REQ_STR_E,
        'F' => REQ_STR_F,
        'C' => REQ_STR_C,
        'D' => REQ_STR_D,
        'H' => REQ_STR_H,
        'S' => REQ_STR_S,
        'X' => REQ_STR_X,
        'd' => REQ_STR_COPY_DATA,
        'c' => REQ_STR_COPY_DONE,
        'f' => REQ_STR_COPY_FAIL,
        _ => "",
    }
}

// reference https://www.postgresql.org/docs/current/errcodes-appendix.html

// 03/0A/0B/0F/0L/0P/20/22/23/26/2F/34/3D/3F/42: client error
// 08/09/0Z/21/24/25/27/28/2B/2D/38/39/3B/40/44/53/54/55/57/5/72/F0/HV/P0/XX: server error
pub(super) fn get_code_desc(code: &str) -> (&'static str, L7ResponseStatus) {
    match code {
        // client error
        "03000" => (
            "sql_statement_not_yet_complete",
            L7ResponseStatus::ClientError,
        ),
        "0A000" => ("feature_not_supported", L7ResponseStatus::ClientError),
        "0B000" => (
            "invalid_transaction_initiation",
            L7ResponseStatus::ClientError,
        ),
        "0F000" => ("locator_exception", L7ResponseStatus::ClientError),
        "0F001" => (
            "invalid_locator_specification",
            L7ResponseStatus::ClientError,
        ),
        "0L000" => ("invalid_grantor", L7ResponseStatus::ClientError),
        "0LP01" => ("invalid_grant_operation", L7ResponseStatus::ClientError),
        "0P000" => ("invalid_role_specification", L7ResponseStatus::ClientError),
        "20000" => ("case_not_found", L7ResponseStatus::ClientError),
        "22000" => ("data_exception", L7ResponseStatus::ClientError),
        "2202E" => ("array_subscript_error", L7ResponseStatus::ClientError),
        "22021" => ("character_not_in_repertoire", L7ResponseStatus::ClientError),
        "22008" => ("datetime_field_overflow", L7ResponseStatus::ClientError),
        "22012" => ("division_by_zero", L7ResponseStatus::ClientError),
        "22005" => ("error_in_assignment", L7ResponseStatus::ClientError),
        "2200B" => ("escape_character_conflict", L7ResponseStatus::ClientError),
        "22022" => ("indicator_overflow", L7ResponseStatus::ClientError),
        "22015" => ("interval_field_overflow", L7ResponseStatus::ClientError),
        "2201E" => (
            "invalid_argument_for_logarithm",
            L7ResponseStatus::ClientError,
        ),
        "22014" => (
            "invalid_argument_for_ntile_function",
            L7ResponseStatus::ClientError,
        ),
        "22016" => (
            "invalid_argument_for_nth_value_function",
            L7ResponseStatus::ClientError,
        ),
        "2201F" => (
            "invalid_argument_for_power_function",
            L7ResponseStatus::ClientError,
        ),
        "2201G" => (
            "invalid_argument_for_width_bucket_function",
            L7ResponseStatus::ClientError,
        ),
        "22018" => (
            "invalid_character_value_for_cast",
            L7ResponseStatus::ClientError,
        ),
        "22007" => ("invalid_datetime_format", L7ResponseStatus::ClientError),
        "22019" => ("invalid_escape_character", L7ResponseStatus::ClientError),
        "2200D" => ("invalid_escape_octet", L7ResponseStatus::ClientError),
        "22025" => ("invalid_escape_sequence", L7ResponseStatus::ClientError),
        "22P06" => (
            "nonstandard_use_of_escape_character",
            L7ResponseStatus::ClientError,
        ),
        "22010" => (
            "invalid_indicator_parameter_value",
            L7ResponseStatus::ClientError,
        ),
        "22023" => ("invalid_parameter_value", L7ResponseStatus::ClientError),
        "22013" => (
            "invalid_preceding_or_following_size",
            L7ResponseStatus::ClientError,
        ),
        "2201B" => ("invalid_regular_expression", L7ResponseStatus::ClientError),
        "2201W" => (
            "invalid_row_count_in_limit_clause",
            L7ResponseStatus::ClientError,
        ),
        "2201X" => (
            "invalid_row_count_in_result_offset_clause",
            L7ResponseStatus::ClientError,
        ),
        "2202H" => (
            "invalid_tablesample_argument",
            L7ResponseStatus::ClientError,
        ),
        "2202G" => ("invalid_tablesample_repeat", L7ResponseStatus::ClientError),
        "22009" => (
            "invalid_time_zone_displacement_value",
            L7ResponseStatus::ClientError,
        ),
        "2200C" => (
            "invalid_use_of_escape_character",
            L7ResponseStatus::ClientError,
        ),
        "2200G" => ("most_specific_type_mismatch", L7ResponseStatus::ClientError),
        "22004" => ("null_value_not_allowed", L7ResponseStatus::ClientError),
        "22002" => (
            "null_value_no_indicator_parameter",
            L7ResponseStatus::ClientError,
        ),
        "22003" => ("numeric_value_out_of_range", L7ResponseStatus::ClientError),
        "2200H" => (
            "sequence_generator_limit_exceeded",
            L7ResponseStatus::ClientError,
        ),
        "22026" => ("string_data_length_mismatch", L7ResponseStatus::ClientError),
        "22001" => (
            "string_data_right_truncation",
            L7ResponseStatus::ClientError,
        ),
        "22011" => ("substring_error", L7ResponseStatus::ClientError),
        "22027" => ("trim_error", L7ResponseStatus::ClientError),
        "22024" => ("unterminated_c_string", L7ResponseStatus::ClientError),
        "2200F" => (
            "zero_length_character_string",
            L7ResponseStatus::ClientError,
        ),
        "22P01" => ("floating_point_exception", L7ResponseStatus::ClientError),
        "22P02" => ("invalid_text_representation", L7ResponseStatus::ClientError),
        "22P03" => (
            "invalid_binary_representation",
            L7ResponseStatus::ClientError,
        ),
        "22P04" => ("bad_copy_file_format", L7ResponseStatus::ClientError),
        "22P05" => ("untranslatable_character", L7ResponseStatus::ClientError),
        "2200L" => ("not_an_xml_document", L7ResponseStatus::ClientError),
        "2200M" => ("invalid_xml_document", L7ResponseStatus::ClientError),
        "2200N" => ("invalid_xml_content", L7ResponseStatus::ClientError),
        "2200S" => ("invalid_xml_comment", L7ResponseStatus::ClientError),
        "2200T" => (
            "invalid_xml_processing_instruction",
            L7ResponseStatus::ClientError,
        ),
        "22030" => (
            "duplicate_json_object_key_value",
            L7ResponseStatus::ClientError,
        ),
        "22031" => (
            "invalid_argument_for_sql_json_datetime_function",
            L7ResponseStatus::ClientError,
        ),
        "22032" => ("invalid_json_text", L7ResponseStatus::ClientError),
        "22033" => ("invalid_sql_json_subscript", L7ResponseStatus::ClientError),
        "22034" => ("more_than_one_sql_json_item", L7ResponseStatus::ClientError),
        "22035" => ("no_sql_json_item", L7ResponseStatus::ClientError),
        "22036" => ("non_numeric_sql_json_item", L7ResponseStatus::ClientError),
        "22037" => (
            "non_unique_keys_in_a_json_object",
            L7ResponseStatus::ClientError,
        ),
        "22038" => (
            "singleton_sql_json_item_required",
            L7ResponseStatus::ClientError,
        ),
        "22039" => ("sql_json_array_not_found", L7ResponseStatus::ClientError),
        "2203A" => ("sql_json_member_not_found", L7ResponseStatus::ClientError),
        "2203B" => ("sql_json_number_not_found", L7ResponseStatus::ClientError),
        "2203C" => ("sql_json_object_not_found", L7ResponseStatus::ClientError),
        "2203D" => (
            "too_many_json_array_elements",
            L7ResponseStatus::ClientError,
        ),
        "2203E" => (
            "too_many_json_object_members",
            L7ResponseStatus::ClientError,
        ),
        "2203F" => ("sql_json_scalar_required", L7ResponseStatus::ClientError),
        "2203G" => (
            "sql_json_item_cannot_be_cast_to_target_type",
            L7ResponseStatus::ClientError,
        ),
        "23000" => (
            "integrity_constraint_violation",
            L7ResponseStatus::ClientError,
        ),
        "23001" => ("restrict_violation", L7ResponseStatus::ClientError),
        "23502" => ("not_null_violation", L7ResponseStatus::ClientError),
        "23503" => ("foreign_key_violation", L7ResponseStatus::ClientError),
        "23505" => ("unique_violation", L7ResponseStatus::ClientError),
        "23514" => ("check_violation", L7ResponseStatus::ClientError),
        "23P01" => ("exclusion_violation", L7ResponseStatus::ClientError),
        "26000" => ("invalid_sql_statement_name", L7ResponseStatus::ClientError),
        "2F000" => ("sql_routine_exception", L7ResponseStatus::ClientError),
        "2F005" => (
            "function_executed_no_return_statement",
            L7ResponseStatus::ClientError,
        ),
        "2F002" => (
            "modifying_sql_data_not_permitted",
            L7ResponseStatus::ClientError,
        ),
        "2F003" => (
            "prohibited_sql_statement_attempted",
            L7ResponseStatus::ClientError,
        ),
        "2F004" => (
            "reading_sql_data_not_permitted",
            L7ResponseStatus::ClientError,
        ),
        "34000" => ("invalid_cursor_name", L7ResponseStatus::ClientError),
        "3D000" => ("invalid_catalog_name", L7ResponseStatus::ClientError),
        "3F000" => ("invalid_schema_name", L7ResponseStatus::ClientError),
        "40001" => ("serialization_failure", L7ResponseStatus::ClientError),
        "40003" => (
            "statement_completion_unknown",
            L7ResponseStatus::ClientError,
        ),
        "40P01" => ("deadlock_detected", L7ResponseStatus::ClientError),
        "42000" => (
            "syntax_error_or_access_rule_violation",
            L7ResponseStatus::ClientError,
        ),
        "42601" => ("syntax_error", L7ResponseStatus::ClientError),
        "42501" => ("insufficient_privilege", L7ResponseStatus::ClientError),
        "42846" => ("cannot_coerce", L7ResponseStatus::ClientError),
        "42803" => ("grouping_error", L7ResponseStatus::ClientError),
        "42P20" => ("windowing_error", L7ResponseStatus::ClientError),
        "42P19" => ("invalid_recursion", L7ResponseStatus::ClientError),
        "42830" => ("invalid_foreign_key", L7ResponseStatus::ClientError),
        "42602" => ("invalid_name", L7ResponseStatus::ClientError),
        "42622" => ("name_too_long", L7ResponseStatus::ClientError),
        "42939" => ("reserved_name", L7ResponseStatus::ClientError),
        "42804" => ("datatype_mismatch", L7ResponseStatus::ClientError),
        "42P18" => ("indeterminate_datatype", L7ResponseStatus::ClientError),
        "42P21" => ("collation_mismatch", L7ResponseStatus::ClientError),
        "42P22" => ("indeterminate_collation", L7ResponseStatus::ClientError),
        "42809" => ("wrong_object_type", L7ResponseStatus::ClientError),
        "428C9" => ("generated_always", L7ResponseStatus::ClientError),
        "42703" => ("undefined_column", L7ResponseStatus::ClientError),
        "42883" => ("undefined_function", L7ResponseStatus::ClientError),
        "42P01" => ("undefined_table", L7ResponseStatus::ClientError),
        "42P02" => ("undefined_parameter", L7ResponseStatus::ClientError),
        "42704" => ("undefined_object", L7ResponseStatus::ClientError),
        "42701" => ("duplicate_column", L7ResponseStatus::ClientError),
        "42P03" => ("duplicate_cursor", L7ResponseStatus::ClientError),
        "42P04" => ("duplicate_database", L7ResponseStatus::ClientError),
        "42723" => ("duplicate_function", L7ResponseStatus::ClientError),
        "42P05" => (
            "duplicate_prepared_statement",
            L7ResponseStatus::ClientError,
        ),
        "42P06" => ("duplicate_schema", L7ResponseStatus::ClientError),
        "42P07" => ("duplicate_table", L7ResponseStatus::ClientError),
        "42712" => ("duplicate_alias", L7ResponseStatus::ClientError),
        "42710" => ("duplicate_object", L7ResponseStatus::ClientError),
        "42702" => ("ambiguous_column", L7ResponseStatus::ClientError),
        "42725" => ("ambiguous_function", L7ResponseStatus::ClientError),
        "42P08" => ("ambiguous_parameter", L7ResponseStatus::ClientError),
        "42P09" => ("ambiguous_alias", L7ResponseStatus::ClientError),
        "42P10" => ("invalid_column_reference", L7ResponseStatus::ClientError),
        "42611" => ("invalid_column_definition", L7ResponseStatus::ClientError),
        "42P11" => ("invalid_cursor_definition", L7ResponseStatus::ClientError),
        "42P12" => ("invalid_database_definition", L7ResponseStatus::ClientError),
        "42P13" => ("invalid_function_definition", L7ResponseStatus::ClientError),
        "42P14" => (
            "invalid_prepared_statement_definition",
            L7ResponseStatus::ClientError,
        ),
        "42P15" => ("invalid_schema_definition", L7ResponseStatus::ClientError),
        "42P16" => ("invalid_table_definition", L7ResponseStatus::ClientError),
        "42P17" => ("invalid_object_definition", L7ResponseStatus::ClientError),

        // server error
        "0Z000" => ("diagnostics_exception", L7ResponseStatus::ServerError),
        "0Z002" => (
            "stacked_diagnostics_accessed_without_active_handler",
            L7ResponseStatus::ServerError,
        ),
        "08000" => ("connection_exception", L7ResponseStatus::ServerError),
        "08003" => ("connection_does_not_exist", L7ResponseStatus::ServerError),
        "08006" => ("connection_failure", L7ResponseStatus::ServerError),
        "08001" => (
            "sqlclient_unable_to_establish_sqlconnection",
            L7ResponseStatus::ServerError,
        ),
        "08004" => (
            "sqlserver_rejected_establishment_of_sqlconnection",
            L7ResponseStatus::ServerError,
        ),
        "08007" => (
            "transaction_resolution_unknown",
            L7ResponseStatus::ServerError,
        ),
        "08P01" => ("protocol_violation", L7ResponseStatus::ServerError),
        "09000" => ("triggered_action_exception", L7ResponseStatus::ServerError),
        "21000" => ("cardinality_violation", L7ResponseStatus::ServerError),
        "24000" => ("invalid_cursor_state", L7ResponseStatus::ServerError),
        "25000" => ("invalid_transaction_state", L7ResponseStatus::ServerError),
        "25001" => ("active_sql_transaction", L7ResponseStatus::ServerError),
        "25002" => (
            "branch_transaction_already_active",
            L7ResponseStatus::ServerError,
        ),
        "25008" => (
            "held_cursor_requires_same_isolation_level",
            L7ResponseStatus::ServerError,
        ),
        "25003" => (
            "inappropriate_access_mode_for_branch_transaction",
            L7ResponseStatus::ServerError,
        ),
        "25004" => (
            "inappropriate_isolation_level_for_branch_transaction",
            L7ResponseStatus::ServerError,
        ),
        "25005" => (
            "no_active_sql_transaction_for_branch_transaction",
            L7ResponseStatus::ServerError,
        ),
        "25006" => ("read_only_sql_transaction", L7ResponseStatus::ServerError),
        "25007" => (
            "schema_and_data_statement_mixing_not_supported",
            L7ResponseStatus::ServerError,
        ),
        "25P01" => ("no_active_sql_transaction", L7ResponseStatus::ServerError),
        "25P02" => ("in_failed_sql_transaction", L7ResponseStatus::ServerError),
        "25P03" => (
            "idle_in_transaction_session_timeout",
            L7ResponseStatus::ServerError,
        ),
        "27000" => (
            "triggered_data_change_violation",
            L7ResponseStatus::ServerError,
        ),
        "28000" => (
            "invalid_authorization_specification",
            L7ResponseStatus::ServerError,
        ),
        "28P01" => ("invalid_password", L7ResponseStatus::ServerError),
        "2B000" => (
            "dependent_privilege_descriptors_still_exist",
            L7ResponseStatus::ServerError,
        ),
        "2BP01" => (
            "dependent_objects_still_exist",
            L7ResponseStatus::ServerError,
        ),
        "2D000" => (
            "invalid_transaction_termination",
            L7ResponseStatus::ServerError,
        ),
        "38000" => ("external_routine_exception", L7ResponseStatus::ServerError),
        "38001" => (
            "containing_sql_not_permitted",
            L7ResponseStatus::ServerError,
        ),
        "38002" => (
            "modifying_sql_data_not_permitted",
            L7ResponseStatus::ServerError,
        ),
        "38003" => (
            "prohibited_sql_statement_attempted",
            L7ResponseStatus::ServerError,
        ),
        "38004" => (
            "reading_sql_data_not_permitted",
            L7ResponseStatus::ServerError,
        ),
        "39000" => (
            "external_routine_invocation_exception",
            L7ResponseStatus::ServerError,
        ),
        "39001" => ("invalid_sqlstate_returned", L7ResponseStatus::ServerError),
        "39004" => ("null_value_not_allowed", L7ResponseStatus::ServerError),
        "39P01" => ("trigger_protocol_violated", L7ResponseStatus::ServerError),
        "39P02" => ("srf_protocol_violated", L7ResponseStatus::ServerError),
        "39P03" => (
            "event_trigger_protocol_violated",
            L7ResponseStatus::ServerError,
        ),
        "3B000" => ("savepoint_exception", L7ResponseStatus::ServerError),
        "3B001" => (
            "invalid_savepoint_specification",
            L7ResponseStatus::ServerError,
        ),
        "40000" => ("transaction_rollback", L7ResponseStatus::ServerError),
        "40002" => (
            "transaction_integrity_constraint_violation",
            L7ResponseStatus::ServerError,
        ),
        "44000" => ("with_check_option_violation", L7ResponseStatus::ServerError),
        "53000" => ("insufficient_resources", L7ResponseStatus::ServerError),
        "53100" => ("disk_full", L7ResponseStatus::ServerError),
        "53200" => ("out_of_memory", L7ResponseStatus::ServerError),
        "53300" => ("too_many_connections", L7ResponseStatus::ServerError),
        "53400" => (
            "configuration_limit_exceeded",
            L7ResponseStatus::ServerError,
        ),
        "54000" => ("program_limit_exceeded", L7ResponseStatus::ServerError),
        "54001" => ("statement_too_complex", L7ResponseStatus::ServerError),
        "54011" => ("too_many_columns", L7ResponseStatus::ServerError),
        "54023" => ("too_many_arguments", L7ResponseStatus::ServerError),
        "55000" => (
            "object_not_in_prerequisite_state",
            L7ResponseStatus::ServerError,
        ),
        "55006" => ("object_in_use", L7ResponseStatus::ServerError),
        "55P02" => ("cant_change_runtime_param", L7ResponseStatus::ServerError),
        "55P03" => ("lock_not_available", L7ResponseStatus::ServerError),
        "55P04" => ("unsafe_new_enum_value_usage", L7ResponseStatus::ServerError),
        "57000" => ("operator_intervention", L7ResponseStatus::ServerError),
        "57014" => ("query_canceled", L7ResponseStatus::ServerError),
        "57P01" => ("admin_shutdown", L7ResponseStatus::ServerError),
        "57P02" => ("crash_shutdown", L7ResponseStatus::ServerError),
        "57P03" => ("cannot_connect_now", L7ResponseStatus::ServerError),
        "57P04" => ("database_dropped", L7ResponseStatus::ServerError),
        "57P05" => ("idle_session_timeout", L7ResponseStatus::ServerError),
        "58000" => ("system_error", L7ResponseStatus::ServerError),
        "58030" => ("io_error", L7ResponseStatus::ServerError),
        "58P01" => ("undefined_file", L7ResponseStatus::ServerError),
        "58P02" => ("duplicate_file", L7ResponseStatus::ServerError),
        "72000" => ("snapshot_too_old", L7ResponseStatus::ServerError),
        "F0000" => ("config_file_error", L7ResponseStatus::ServerError),
        "F0001" => ("lock_file_exists", L7ResponseStatus::ServerError),
        "HV000" => ("fdw_error", L7ResponseStatus::ServerError),
        "HV005" => ("fdw_column_name_not_found", L7ResponseStatus::ServerError),
        "HV002" => (
            "fdw_dynamic_parameter_value_needed",
            L7ResponseStatus::ServerError,
        ),
        "HV010" => ("fdw_function_sequence_error", L7ResponseStatus::ServerError),
        "HV021" => (
            "fdw_inconsistent_descriptor_information",
            L7ResponseStatus::ServerError,
        ),
        "HV024" => ("fdw_invalid_attribute_value", L7ResponseStatus::ServerError),
        "HV007" => ("fdw_invalid_column_name", L7ResponseStatus::ServerError),
        "HV008" => ("fdw_invalid_column_number", L7ResponseStatus::ServerError),
        "HV004" => ("fdw_invalid_data_type", L7ResponseStatus::ServerError),
        "HV006" => (
            "fdw_invalid_data_type_descriptors",
            L7ResponseStatus::ServerError,
        ),
        "HV091" => (
            "fdw_invalid_descriptor_field_identifier",
            L7ResponseStatus::ServerError,
        ),
        "HV00B" => ("fdw_invalid_handle", L7ResponseStatus::ServerError),
        "HV00C" => ("fdw_invalid_option_index", L7ResponseStatus::ServerError),
        "HV00D" => ("fdw_invalid_option_name", L7ResponseStatus::ServerError),
        "HV090" => (
            "fdw_invalid_string_length_or_buffer_length",
            L7ResponseStatus::ServerError,
        ),
        "HV00A" => ("fdw_invalid_string_format", L7ResponseStatus::ServerError),
        "HV009" => (
            "fdw_invalid_use_of_null_pointer",
            L7ResponseStatus::ServerError,
        ),
        "HV014" => ("fdw_too_many_handles", L7ResponseStatus::ServerError),
        "HV001" => ("fdw_out_of_memory", L7ResponseStatus::ServerError),
        "HV00P" => ("fdw_no_schemas", L7ResponseStatus::ServerError),
        "HV00J" => ("fdw_option_name_not_found", L7ResponseStatus::ServerError),
        "HV00K" => ("fdw_reply_handle", L7ResponseStatus::ServerError),
        "HV00Q" => ("fdw_schema_not_found", L7ResponseStatus::ServerError),
        "HV00R" => ("fdw_table_not_found", L7ResponseStatus::ServerError),
        "HV00L" => (
            "fdw_unable_to_create_execution",
            L7ResponseStatus::ServerError,
        ),
        "HV00M" => ("fdw_unable_to_create_reply", L7ResponseStatus::ServerError),
        "HV00N" => (
            "fdw_unable_to_establish_connection",
            L7ResponseStatus::ServerError,
        ),
        "P0000" => ("plpgsql_error", L7ResponseStatus::ServerError),
        "P0001" => ("raise_exception", L7ResponseStatus::ServerError),
        "P0002" => ("no_data_found", L7ResponseStatus::ServerError),
        "P0003" => ("too_many_rows", L7ResponseStatus::ServerError),
        "P0004" => ("assert_failure", L7ResponseStatus::ServerError),
        "XX000" => ("internal_error", L7ResponseStatus::ServerError),
        "XX001" => ("data_corrupted", L7ResponseStatus::ServerError),
        "XX002" => ("index_corrupted", L7ResponseStatus::ServerError),
        // default
        _ => ("", L7ResponseStatus::NotExist),
    }
}
