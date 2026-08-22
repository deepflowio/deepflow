# Name                     , DisplayName                  , Description
time_str                  , time_str                    ,
_id                       , _id                         ,
time                      , time                        ,
start_time                , start_time                  ,
end_time                  , end_time                    ,
region                    , region                      ,
pod                       , pod                         ,
gprocess                  , gprocess                    ,
gprocess.biz_type         , 进程业务类型                  ,
ip                        , ip                          ,
is_ipv4                   , is_ipv4                     ,

event_type                , event_type                  ,
process_kname             , process_kname               ,
app_instance              , app_instance                ,
agent                     , agent                       ,
signal_source             , signal_source               ,
rule_id                   , 规则 ID                     , 命中的阻断规则 ID
target_type               , 阻断目标类型                 , exec 或 syscall
action                    , 处置动作                    , audit、deny 或 sigkill
mechanism                 , 阻断机制                    , lsm、kprobe_override、sigkill、seccomp 或 user_space_audit
guarantee                 , 阻断保证                    , prevented、best_effort 或 audit_only
errno                     , errno                       , 返回给进程的错误码
pid                       , pid                         ,
parent_pid                , parent_pid                  ,
root_pid                  , root_pid                    ,
uid                       , uid                         ,
gid                       , gid                         ,
cmdline                   , cmdline                     ,
exec_path                 , exec_path                   ,
syscall_name              , syscall_name                ,
syscall_id                , syscall_id                  ,
policy_epoch              , policy_epoch                , 策略版本
syscall_thread            , syscall_thread              ,
syscall_coroutine         , syscall_coroutine           ,
