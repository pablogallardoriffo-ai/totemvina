-- ════════════════════════════════════════════════════════════════════════════
--  Tótem Viña · Endurecimiento del acceso de administración
--  Fecha: 2026-08-25 · aplicada al proyecto duoc-portal-salas el 2026-08-26
--
--  PROBLEMA
--  La clave maestra del panel vivía en claro en `totem_config.admin_pin`, una
--  tabla que la clave anónima de Supabase podía leer. Como esa clave anónima
--  está —y debe estar— en el HTML público, cualquiera que abriera F12 podía:
--    · leer la contraseña en la respuesta de `/rest/v1/totem_config`,
--    · leerla en `localStorage.totem_admin_pin`,
--    · recibirla por Realtime al cambiarla,
--    · o directamente saltarse el panel y escribir en las tablas del tótem,
--      porque `anon` tenía INSERT/UPDATE/DELETE sobre todas ellas.
--
--  SOLUCIÓN
--  1. La contraseña pasa a guardarse como hash bcrypt en una tabla sin ninguna
--     política para `anon`: es invisible para el navegador.
--  2. La verificación ocurre en el servidor (RPC `totem_admin_login`), con
--     límite de intentos por IP, y devuelve un token de sesión de 8 horas.
--  3. Toda escritura de administración pasa por funciones SECURITY DEFINER que
--     exigen ese token. Se le quitan a `anon` los permisos de escritura.
--  4. Los datos personales de las encuestas (nombre/correo) y los Excel
--     originales dejan de ser legibles con la clave anónima.
-- ════════════════════════════════════════════════════════════════════════════


-- ─── 1. Almacén de la credencial ────────────────────────────────────────────
-- Sin políticas RLS: PostgREST con la clave anónima no puede verla ni tocarla.
-- Solo se alcanza a través de las funciones SECURITY DEFINER de más abajo.

create table if not exists public.totem_admin_cred (
    id             smallint primary key default 1 check (id = 1),
    pin_hash       text        not null,
    actualizado_en timestamptz not null default now()
);
alter table public.totem_admin_cred enable row level security;
revoke all on public.totem_admin_cred from anon, authenticated;

create table if not exists public.totem_admin_sesion (
    token     text primary key,
    cliente   text,
    creada_en timestamptz not null default now(),
    expira_en timestamptz not null
);
create index if not exists totem_admin_sesion_expira_idx
    on public.totem_admin_sesion (expira_en);
alter table public.totem_admin_sesion enable row level security;
revoke all on public.totem_admin_sesion from anon, authenticated;

-- Historial corto de intentos, para frenar la fuerza bruta por IP.
create table if not exists public.totem_admin_intento (
    id        bigserial primary key,
    cliente   text        not null,
    exito     boolean     not null,
    creado_en timestamptz not null default now()
);
create index if not exists totem_admin_intento_cliente_idx
    on public.totem_admin_intento (cliente, creado_en desc);
alter table public.totem_admin_intento enable row level security;
revoke all on public.totem_admin_intento from anon, authenticated;
revoke all on sequence public.totem_admin_intento_id_seq from anon, authenticated;


-- ─── 2. Migrar el PIN en claro a hash y borrar el original ──────────────────
-- El valor en claro nunca sale de la base de datos: se lee, se hashea y se
-- elimina dentro de la misma transacción.

insert into public.totem_admin_cred (id, pin_hash)
select 1, extensions.crypt(c.value, extensions.gen_salt('bf', 10))
  from public.totem_config c
 where c.key = 'admin_pin'
   and coalesce(c.value, '') <> ''
on conflict (id) do nothing;

-- Si la fila no existía, se siembra la clave por defecto histórica para no
-- dejar el panel inaccesible. Debe cambiarse desde el panel apenas se despliegue.
insert into public.totem_admin_cred (id, pin_hash)
select 1, extensions.crypt('010203', extensions.gen_salt('bf', 10))
 where not exists (select 1 from public.totem_admin_cred where id = 1);

delete from public.totem_config where key = 'admin_pin';


-- ─── 3. Guardián de sesión (interno, no expuesto a anon) ────────────────────

create or replace function public.totem_admin_exigir(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $fn$
begin
    if p_token is null or not exists (
        select 1 from public.totem_admin_sesion
         where token = p_token and expira_en > now()
    ) then
        raise exception 'SESION_ADMIN_INVALIDA'
            using errcode = '42501',
                  hint    = 'Vuelve a ingresar la clave del panel.';
    end if;
end;
$fn$;
revoke all on function public.totem_admin_exigir(text) from public, anon, authenticated;


-- ─── 4. Inicio y cierre de sesión ───────────────────────────────────────────

create or replace function public.totem_admin_login(p_pin text, p_cliente text default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_ip     text := '';
    v_clave  text;
    v_fallos int;
    v_hash   text;
    v_token  text;
    v_expira timestamptz;
begin
    -- La IP la pone el proxy de Supabase, no el cliente: es la única parte del
    -- identificador que el navegador no puede falsear a voluntad.
    begin
        v_ip := split_part(
            coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''),
            ',', 1);
    exception when others then
        v_ip := '';
    end;
    v_clave := coalesce(nullif(trim(v_ip), ''), nullif(trim(p_cliente), ''), 'desconocido');

    -- Limpieza oportunista: sesiones vencidas e intentos viejos.
    delete from public.totem_admin_sesion  where expira_en < now();
    delete from public.totem_admin_intento where creado_en < now() - interval '1 day';

    select count(*) into v_fallos
      from public.totem_admin_intento
     where cliente = v_clave
       and not exito
       and creado_en > now() - interval '15 minutes';

    if v_fallos >= 5 then
        return jsonb_build_object('ok', false, 'motivo', 'bloqueado', 'espera_min', 15);
    end if;

    select pin_hash into v_hash from public.totem_admin_cred where id = 1;

    if v_hash is null
       or p_pin is null
       or extensions.crypt(p_pin, v_hash) <> v_hash then
        insert into public.totem_admin_intento (cliente, exito) values (v_clave, false);
        return jsonb_build_object('ok', false, 'motivo', 'pin',
                                  'restantes', greatest(0, 4 - v_fallos));
    end if;

    delete from public.totem_admin_intento where cliente = v_clave and not exito;

    v_token  := encode(extensions.gen_random_bytes(32), 'hex');
    v_expira := now() + interval '8 hours';
    insert into public.totem_admin_sesion (token, cliente, expira_en)
         values (v_token, v_clave, v_expira);

    return jsonb_build_object('ok', true, 'token', v_token, 'expira_en', v_expira);
end;
$fn$;

create or replace function public.totem_admin_logout(p_token text)
returns void
language sql
security definer
set search_path = public
as $fn$
    delete from public.totem_admin_sesion where token = p_token;
$fn$;

create or replace function public.totem_admin_sesion_activa(p_token text)
returns boolean
language sql
security definer
stable
set search_path = public
as $fn$
    select exists (
        select 1 from public.totem_admin_sesion
         where token = p_token and expira_en > now()
    );
$fn$;


-- ─── 5. Cambio de clave ─────────────────────────────────────────────────────

create or replace function public.totem_admin_cambiar_pin(p_token text, p_actual text, p_nueva text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_hash text;
begin
    perform public.totem_admin_exigir(p_token);

    select pin_hash into v_hash from public.totem_admin_cred where id = 1;
    if v_hash is null or extensions.crypt(coalesce(p_actual, ''), v_hash) <> v_hash then
        return jsonb_build_object('ok', false, 'motivo', 'actual');
    end if;
    if length(coalesce(p_nueva, '')) < 6 then
        return jsonb_build_object('ok', false, 'motivo', 'corta');
    end if;
    if extensions.crypt(p_nueva, v_hash) = v_hash then
        return jsonb_build_object('ok', false, 'motivo', 'igual');
    end if;

    update public.totem_admin_cred
       set pin_hash       = extensions.crypt(p_nueva, extensions.gen_salt('bf', 10)),
           actualizado_en = now()
     where id = 1;

    -- Cambiar la clave cierra cualquier otra sesión abierta.
    delete from public.totem_admin_sesion where token <> p_token;

    return jsonb_build_object('ok', true);
end;
$fn$;


-- ─── 6. Escrituras de administración ────────────────────────────────────────

-- Solo las claves de la lista blanca: así nadie puede volver a crear una fila
-- `admin_pin` en `totem_config`.
create or replace function public.totem_admin_set_config(p_token text, p_key text, p_value text)
returns boolean
language plpgsql
security definer
set search_path = public
as $fn$
begin
    perform public.totem_admin_exigir(p_token);

    if p_key is null or p_key not in
        ('vista_publica', 'titulo_totem', 'barra_info', 'suspension_seg', 'bloques_lote') then
        raise exception 'CLAVE_CONFIG_NO_PERMITIDA: %', coalesce(p_key, '(nula)')
            using errcode = '22023';
    end if;

    insert into public.totem_config (key, value, updated_at)
         values (p_key, p_value, now())
    on conflict (key) do update
            set value = excluded.value, updated_at = now();
    return true;
end;
$fn$;

create or replace function public.totem_admin_guardar_sabana(
    p_token text, p_data jsonb, p_meta jsonb, p_base64 text, p_nombre text)
returns timestamptz
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_ahora timestamptz := now();
begin
    perform public.totem_admin_exigir(p_token);

    insert into public.totem_sabana
        (id, data, meta_eventos, archivo_base64, archivo_nombre, total_filas, actualizado_en)
    values
        (1, coalesce(p_data, '[]'::jsonb), coalesce(p_meta, '{}'::jsonb),
         p_base64, p_nombre, coalesce(jsonb_array_length(p_data), 0), v_ahora)
    on conflict (id) do update
        set data           = excluded.data,
            meta_eventos   = excluded.meta_eventos,
            archivo_base64 = excluded.archivo_base64,
            archivo_nombre = excluded.archivo_nombre,
            total_filas    = excluded.total_filas,
            actualizado_en = excluded.actualizado_en;

    insert into public.totem_sabana_signal (id, version) values (1, v_ahora)
    on conflict (id) do update set version = excluded.version;

    return v_ahora;
end;
$fn$;

create or replace function public.totem_admin_guardar_examenes(
    p_token text, p_data jsonb, p_base64 text, p_nombre text)
returns timestamptz
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_ahora timestamptz := now();
begin
    perform public.totem_admin_exigir(p_token);

    insert into public.totem_examenes
        (id, data, archivo_base64, archivo_nombre, total_filas, actualizado_en)
    values
        (1, coalesce(p_data, '[]'::jsonb), p_base64, p_nombre,
         coalesce(jsonb_array_length(p_data), 0), v_ahora)
    on conflict (id) do update
        set data           = excluded.data,
            archivo_base64 = excluded.archivo_base64,
            archivo_nombre = excluded.archivo_nombre,
            total_filas    = excluded.total_filas,
            actualizado_en = excluded.actualizado_en;

    insert into public.totem_examenes_signal (id, version) values (1, v_ahora)
    on conflict (id) do update set version = excluded.version;

    return v_ahora;
end;
$fn$;

create or replace function public.totem_admin_borrar_examenes(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $fn$
begin
    perform public.totem_admin_exigir(p_token);
    delete from public.totem_examenes where id = 1;
    insert into public.totem_examenes_signal (id, version) values (1, now())
    on conflict (id) do update set version = excluded.version;
end;
$fn$;

-- Los bloques se suben por trozos con el lote todavía inactivo; el tótem sigue
-- mostrando el lote anterior hasta que `totem_admin_bloques_activar` lo cambia.
create or replace function public.totem_admin_bloques_insertar(
    p_token text, p_lote text, p_filas jsonb)
returns integer
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v_filas integer;
begin
    perform public.totem_admin_exigir(p_token);
    if coalesce(trim(p_lote), '') = '' then
        raise exception 'LOTE_VACIO' using errcode = '22023';
    end if;

    insert into public.totem_bloques
        (lote, ev, seccion, denominacion, fecha, hora_inicio, hora_fin,
         salas, salas_nombre, docentes, tipo_recurso, modulos)
    select p_lote,
           f ->> 'ev',
           f ->> 'seccion',
           f ->> 'denominacion',
           nullif(f ->> 'fecha', '')::date,
           f ->> 'hora_inicio',
           f ->> 'hora_fin',
           f ->> 'salas',
           f ->> 'salas_nombre',
           f ->> 'docentes',
           f ->> 'tipo_recurso',
           nullif(f ->> 'modulos', '')::int
      from jsonb_array_elements(coalesce(p_filas, '[]'::jsonb)) f;

    get diagnostics v_filas = row_count;
    return v_filas;
end;
$fn$;

create or replace function public.totem_admin_bloques_activar(p_token text, p_lote text)
returns void
language plpgsql
security definer
set search_path = public
as $fn$
begin
    perform public.totem_admin_exigir(p_token);

    insert into public.totem_config (key, value, updated_at)
         values ('bloques_lote', p_lote, now())
    on conflict (key) do update set value = excluded.value, updated_at = now();

    insert into public.totem_bloques_signal (id, version) values (1, now())
    on conflict (id) do update set version = excluded.version;

    -- Activado el lote nuevo, los anteriores sobran.
    delete from public.totem_bloques where lote is distinct from p_lote;
end;
$fn$;

create or replace function public.totem_admin_bloques_descartar(p_token text, p_lote text)
returns void
language plpgsql
security definer
set search_path = public
as $fn$
begin
    perform public.totem_admin_exigir(p_token);
    delete from public.totem_bloques where lote = p_lote;
end;
$fn$;


-- ─── 7. Lecturas que dejan de ser públicas ──────────────────────────────────

-- Nombre y correo de quien responde la encuesta son datos personales: solo el
-- panel los ve, y solo con una sesión válida.
create or replace function public.totem_admin_encuestas(p_token text, p_limite integer default 500)
returns table (rating integer, comment text, name text, email text, created_at timestamptz)
language plpgsql
security definer
set search_path = public
as $fn$
begin
    perform public.totem_admin_exigir(p_token);
    return query
        select e.rating, e.comment, e.name, e.email, e.created_at
          from public.totem_encuestas e
         order by e.created_at desc
         limit greatest(1, least(coalesce(p_limite, 500), 2000));
end;
$fn$;

-- El Excel original completo tampoco tiene por qué ser descargable por cualquiera.
create or replace function public.totem_admin_archivo_sabana(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v jsonb;
begin
    perform public.totem_admin_exigir(p_token);
    select jsonb_build_object('nombre', s.archivo_nombre, 'base64', s.archivo_base64)
      into v from public.totem_sabana s where s.id = 1;
    return coalesce(v, '{}'::jsonb);
end;
$fn$;

create or replace function public.totem_admin_archivo_examenes(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $fn$
declare
    v jsonb;
begin
    perform public.totem_admin_exigir(p_token);
    select jsonb_build_object('nombre', e.archivo_nombre, 'base64', e.archivo_base64)
      into v from public.totem_examenes e where e.id = 1;
    return coalesce(v, '{}'::jsonb);
end;
$fn$;


-- ─── 8. Señal de encuestas ──────────────────────────────────────────────────
-- Como `totem_encuestas` deja de ser legible por `anon`, Realtime ya no puede
-- entregarle la fila nueva. En su lugar se publica una señal sin datos (el mismo
-- patrón que sábana/exámenes) y el panel recarga por RPC cuando la ve cambiar.

create table if not exists public.totem_encuestas_signal (
    id      smallint primary key default 1 check (id = 1),
    version timestamptz not null default now()
);
insert into public.totem_encuestas_signal (id, version) values (1, now())
on conflict (id) do nothing;

alter table public.totem_encuestas_signal enable row level security;
drop policy if exists totem_encuestas_signal_select_anon on public.totem_encuestas_signal;
create policy totem_encuestas_signal_select_anon
    on public.totem_encuestas_signal for select to anon using (true);
grant select on public.totem_encuestas_signal to anon;

create or replace function public.totem_encuestas_signal_bump()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn$
begin
    update public.totem_encuestas_signal set version = now() where id = 1;
    return null;
end;
$fn$;

drop trigger if exists totem_encuestas_signal_trg on public.totem_encuestas;
create trigger totem_encuestas_signal_trg
    after insert on public.totem_encuestas
    for each statement execute function public.totem_encuestas_signal_bump();

do $do$
begin
    if not exists (
        select 1 from pg_publication_tables
         where pubname = 'supabase_realtime'
           and schemaname = 'public'
           and tablename = 'totem_encuestas_signal') then
        execute 'alter publication supabase_realtime add table public.totem_encuestas_signal';
    end if;
    -- El canal de bloques nunca recibía nada porque su tabla señal no estaba publicada.
    if not exists (
        select 1 from pg_publication_tables
         where pubname = 'supabase_realtime'
           and schemaname = 'public'
           and tablename = 'totem_bloques_signal') then
        execute 'alter publication supabase_realtime add table public.totem_bloques_signal';
    end if;
end;
$do$;


-- ─── 9. Quitarle a `anon` todo lo que ya no necesita ────────────────────────

-- Configuración: se lee (ya no contiene secretos), no se escribe.
drop policy if exists totem_config_insert_anon on public.totem_config;
drop policy if exists totem_config_update_anon on public.totem_config;
revoke insert, update, delete, truncate on public.totem_config from anon, authenticated;

-- Sábana: se lee todo menos el Excel original.
drop policy if exists totem_sabana_insert_anon        on public.totem_sabana;
drop policy if exists totem_sabana_update_anon        on public.totem_sabana;
drop policy if exists totem_sabana_signal_insert_anon on public.totem_sabana_signal;
drop policy if exists totem_sabana_signal_update_anon on public.totem_sabana_signal;
revoke all on public.totem_sabana from anon, authenticated;
grant select (id, data, meta_eventos, archivo_nombre, total_filas, actualizado_en)
    on public.totem_sabana to anon;
revoke insert, update, delete, truncate on public.totem_sabana_signal from anon, authenticated;

-- Exámenes: idem.
drop policy if exists totem_examenes_insert_anon        on public.totem_examenes;
drop policy if exists totem_examenes_update_anon        on public.totem_examenes;
drop policy if exists totem_examenes_delete_anon        on public.totem_examenes;
drop policy if exists totem_examenes_signal_insert_anon on public.totem_examenes_signal;
drop policy if exists totem_examenes_signal_update_anon on public.totem_examenes_signal;
revoke all on public.totem_examenes from anon, authenticated;
grant select (id, data, archivo_nombre, total_filas, actualizado_en)
    on public.totem_examenes to anon;
revoke insert, update, delete, truncate on public.totem_examenes_signal from anon, authenticated;

-- Bloques: se leen, no se escriben ni se borran.
drop policy if exists totem_bloques_insert_anon        on public.totem_bloques;
drop policy if exists totem_bloques_delete_anon        on public.totem_bloques;
drop policy if exists totem_bloques_signal_insert_anon on public.totem_bloques_signal;
drop policy if exists totem_bloques_signal_update_anon on public.totem_bloques_signal;
revoke insert, update, delete, truncate on public.totem_bloques from anon, authenticated;
revoke insert, update, delete, truncate on public.totem_bloques_signal from anon, authenticated;

-- Encuestas: se responden, no se leen.
drop policy if exists totem_encuestas_select_anon on public.totem_encuestas;
revoke all on public.totem_encuestas from anon, authenticated;
grant insert on public.totem_encuestas to anon;

-- Métricas: se acumulan, no se borran.
drop policy if exists totem_metricas_all_anon    on public.totem_metricas;
drop policy if exists totem_metricas_select_anon on public.totem_metricas;
drop policy if exists totem_metricas_insert_anon on public.totem_metricas;
drop policy if exists totem_metricas_update_anon on public.totem_metricas;
create policy totem_metricas_select_anon on public.totem_metricas for select to anon using (true);
create policy totem_metricas_insert_anon on public.totem_metricas for insert to anon with check (true);
create policy totem_metricas_update_anon on public.totem_metricas for update to anon using (true) with check (true);
revoke delete, truncate on public.totem_metricas from anon, authenticated;

-- Eventos de uso: se registran, no se borran.
revoke update, delete, truncate on public.totem_eventos from anon, authenticated;


-- ─── 10. Permisos de ejecución de las RPC ───────────────────────────────────
-- Postgres concede EXECUTE a PUBLIC en toda función nueva, lo que también dejaría
-- estas RPC al alcance del rol `authenticated`. Se quita ese permiso general y se
-- concede solo a `anon`, el único rol con el que trabaja el tótem.

revoke execute on function public.totem_admin_login(text, text) from public, authenticated;
revoke execute on function public.totem_admin_logout(text) from public, authenticated;
revoke execute on function public.totem_admin_sesion_activa(text) from public, authenticated;
revoke execute on function public.totem_admin_cambiar_pin(text, text, text) from public, authenticated;
revoke execute on function public.totem_admin_set_config(text, text, text) from public, authenticated;
revoke execute on function public.totem_admin_guardar_sabana(text, jsonb, jsonb, text, text) from public, authenticated;
revoke execute on function public.totem_admin_guardar_examenes(text, jsonb, text, text) from public, authenticated;
revoke execute on function public.totem_admin_borrar_examenes(text) from public, authenticated;
revoke execute on function public.totem_admin_bloques_insertar(text, text, jsonb) from public, authenticated;
revoke execute on function public.totem_admin_bloques_activar(text, text) from public, authenticated;
revoke execute on function public.totem_admin_bloques_descartar(text, text) from public, authenticated;
revoke execute on function public.totem_admin_encuestas(text, integer) from public, authenticated;
revoke execute on function public.totem_admin_archivo_sabana(text) from public, authenticated;
revoke execute on function public.totem_admin_archivo_examenes(text) from public, authenticated;

grant execute on function public.totem_admin_login(text, text)                              to anon;
grant execute on function public.totem_admin_logout(text)                                   to anon;
grant execute on function public.totem_admin_sesion_activa(text)                            to anon;
grant execute on function public.totem_admin_cambiar_pin(text, text, text)                  to anon;
grant execute on function public.totem_admin_set_config(text, text, text)                   to anon;
grant execute on function public.totem_admin_guardar_sabana(text, jsonb, jsonb, text, text) to anon;
grant execute on function public.totem_admin_guardar_examenes(text, jsonb, text, text)      to anon;
grant execute on function public.totem_admin_borrar_examenes(text)                          to anon;
grant execute on function public.totem_admin_bloques_insertar(text, text, jsonb)            to anon;
grant execute on function public.totem_admin_bloques_activar(text, text)                    to anon;
grant execute on function public.totem_admin_bloques_descartar(text, text)                  to anon;
grant execute on function public.totem_admin_encuestas(text, integer)                       to anon;
grant execute on function public.totem_admin_archivo_sabana(text)                           to anon;
grant execute on function public.totem_admin_archivo_examenes(text)                         to anon;

-- La función del trigger de encuestas no es una RPC: nadie debe poder invocarla.
revoke execute on function public.totem_encuestas_signal_bump() from public, anon, authenticated;
