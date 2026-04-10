-- Migration for Supabase/Postgres
-- Run in Supabase SQL editor (or psql) in order.

-- 1) settings table (if missing)
create table if not exists public.settings (
  id integer primary key,
  title text not null,
  background_color text not null
);

-- 2) events: add capacity + reservation_mode
alter table public.events
  add column if not exists capacity integer not null default 30;

alter table public.events
  add column if not exists reservation_mode text not null default 'approval';

-- normalize existing rows
update public.events
set reservation_mode = 'approval'
where reservation_mode is null or reservation_mode not in ('approval', 'instant');

-- 3) reservations: add slot_id and helpful index
alter table public.reservations
  add column if not exists slot_id integer null;

create index if not exists reservations_event_id_idx on public.reservations(event_id);
create index if not exists reservations_slot_id_idx on public.reservations(slot_id);

-- 4) event_slots table (optional, for "schools/courses" timeslots)
create table if not exists public.event_slots (
  id bigserial primary key,
  event_id integer not null references public.events(id) on delete cascade,
  start_time text not null,
  capacity integer not null default 30,
  reserved_count integer not null default 0
);

create index if not exists event_slots_event_id_idx on public.event_slots(event_id);

-- 5) news table ("Aktuality")
create table if not exists public.news (
  id bigserial primary key,
  title text not null,
  content text not null,
  date date not null default current_date
);

create index if not exists news_date_idx on public.news(date desc);
