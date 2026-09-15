-- BoardAgent Phase 1 / group 43: atomic trusted-subject rate-limit authority.
-- Runtime roles never mutate global buckets directly. The definer accepts only an
-- HMAC-derived subject digest and returns a content-free generic decision.

create policy boardagent_migrator_rate_limit_authority
  on public.rate_limit_buckets
  for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true) in ('identity','request'))
  with check (current_setting('boardagent.transaction_scope',true) in ('identity','request'));

create function public.boardagent_consume_rate_limit(
  candidate_bucket_class text,
  candidate_subject_sha256 bytea,
  candidate_window_seconds integer,
  candidate_max_requests integer,
  candidate_block_seconds integer
)
returns table(
  result_allowed boolean,
  result_request_count integer,
  result_blocked_until timestamptz,
  result_retry_after_seconds integer
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  transaction_time constant timestamptz := transaction_timestamp();
  current_window timestamptz;
  active_block timestamptz;
  bucket public.rate_limit_buckets%rowtype;
begin
  if coalesce(current_setting('boardagent.transaction_scope',true),'')
       not in ('identity','request') then
    raise exception 'rate-limit consumption requires a managed identity or request transaction'
      using errcode='25000';
  end if;
  if candidate_bucket_class not in ('ip','client','member','token','registration')
     or octet_length(candidate_subject_sha256)<>32
     or candidate_window_seconds not between 1 and 86400
     or candidate_max_requests not between 1 and 1000000
     or candidate_block_seconds not between 1 and 86400 then
    raise exception 'invalid rate-limit policy input' using errcode='22023';
  end if;

  current_window := date_bin(
    make_interval(secs=>candidate_window_seconds),
    transaction_time,
    timestamptz '1970-01-01 00:00:00+00'
  );
  perform pg_advisory_xact_lock(
    hashtextextended(
      candidate_bucket_class || ':' || encode(candidate_subject_sha256,'hex'),
      424243
    )
  );
  select max(existing.blocked_until)
    into active_block
    from public.rate_limit_buckets as existing
   where existing.bucket_class=candidate_bucket_class
     and existing.subject_sha256=candidate_subject_sha256
     and existing.blocked_until>transaction_time;

  insert into public.rate_limit_buckets as stored(
    bucket_class,subject_sha256,window_started_at,window_seconds,request_count,blocked_until
  ) values (
    candidate_bucket_class,candidate_subject_sha256,current_window,
    candidate_window_seconds,1,active_block
  )
  on conflict (bucket_class,subject_sha256,window_started_at) do update
    set request_count=case
          when stored.request_count<candidate_max_requests+1 then stored.request_count+1
          else stored.request_count
        end,
        blocked_until=case
          when active_block is not null then active_block
          when stored.request_count>=candidate_max_requests then greatest(
            transaction_time+make_interval(secs=>candidate_block_seconds),
            current_window+make_interval(secs=>candidate_window_seconds)
          )
          else null
        end
  returning stored.* into bucket;

  result_allowed := active_block is null
    and bucket.request_count<=candidate_max_requests
    and (bucket.blocked_until is null or bucket.blocked_until<=transaction_time);
  result_request_count := bucket.request_count;
  result_blocked_until := bucket.blocked_until;
  result_retry_after_seconds := case
    when result_allowed then 0
    else greatest(
      1,
      ceil(
        extract(
          epoch from (coalesce(bucket.blocked_until,transaction_time)-transaction_time)
        )
      )::integer
    )
  end;
  return next;
end
$$;

alter function public.boardagent_consume_rate_limit(text,bytea,integer,integer,integer)
  owner to boardagent_migrator;
revoke all on function public.boardagent_consume_rate_limit(text,bytea,integer,integer,integer)
  from public;
grant execute on function public.boardagent_consume_rate_limit(text,bytea,integer,integer,integer)
  to boardagent_server;
