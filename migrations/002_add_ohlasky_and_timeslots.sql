-- Add "Ohlášky" to settings + support "timeslots" (variant A).

alter table public.settings
  add column if not exists ohlasky text not null default '';

-- We already have event_slots from previous migration in this project.
-- For variant A, frontend stores human-readable labels; we keep them in `label`.
alter table public.event_slots
  add column if not exists label text;

-- If event_slots table doesn't exist for any reason, create a minimal one.
create table if not exists public.event_slots (
  id bigserial primary key,
  event_id integer not null references public.events(id) on delete cascade,
  label text not null
);

-- Store chosen label on reservation row too.
alter table public.reservations
  add column if not exists timeslot text;

create index if not exists event_slots_event_id_label_idx on public.event_slots(event_id, label);
