-- =====================================================================
--  LOUNGE  ·  upgrade 6: messages expire after 7 days
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

create extension if not exists pg_cron;

-- delete messages older than 7 days, every hour
do $$ begin
  perform cron.unschedule('lounge-expire-messages');
exception when others then null; end $$;

select cron.schedule('lounge-expire-messages', '17 * * * *',
  $$delete from public.messages where created_at < now() - interval '7 days'$$);

-- clear out anything already older than 7 days right now
delete from public.messages where created_at < now() - interval '7 days';

-- let admins delete old image files (the chat cleans them up automatically)
drop policy if exists "admins delete attachments" on storage.objects;
create policy "admins delete attachments" on storage.objects for delete to authenticated
  using (bucket_id = 'attachments' and public.is_admin());
drop policy if exists "admins list attachments" on storage.objects;
create policy "admins list attachments" on storage.objects for select to authenticated
  using (bucket_id = 'attachments' and public.is_admin());
