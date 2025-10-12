-- Developer convenience views (read-only)
-- 1) events_recent: last 1,000 events with readable names
CREATE OR REPLACE VIEW events_recent AS WITH filtered_index AS (
    SELECT event_id,
      ts,
      subject_id
    FROM event_index
    WHERE ts >= now() - interval '7 days'
  )
SELECT e.event_id,
  fi.ts,
  s.subject_key AS subject,
  p.name AS producer,
  sc.name AS schema_name,
  sc.version AS schema_version,
  e.received_at,
  e.payload
FROM filtered_index fi
  JOIN events e ON e.event_id = fi.event_id
  LEFT JOIN subjects s ON s.subject_id = fi.subject_id
  LEFT JOIN producers p ON p.producer_id = e.producer_id
  LEFT JOIN schemas sc ON sc.schema_id = e.schema_id
ORDER BY fi.ts DESC
LIMIT 1000;
-- 2) events_with_tags_recent: last 1,000 events with aggregated tags
CREATE OR REPLACE VIEW events_with_tags_recent AS WITH filtered_index AS (
    SELECT event_id,
      ts,
      subject_id
    FROM event_index
    WHERE ts >= now() - interval '7 days'
  )
SELECT e.event_id,
  fi.ts,
  s.subject_key AS subject,
  p.name AS producer,
  sc.name AS schema_name,
  sc.version AS schema_version,
  jsonb_agg(
    jsonb_build_object(
      'tag_id',
      t.tag_id,
      'key',
      t.key,
      'value',
      t.value
    )
    ORDER BY t.key
  ) FILTER (
    WHERE t.tag_id IS NOT NULL
  ) AS tags,
  e.payload
FROM filtered_index fi
  JOIN events e ON e.event_id = fi.event_id
  LEFT JOIN subjects s ON s.subject_id = fi.subject_id
  LEFT JOIN producers p ON p.producer_id = e.producer_id
  LEFT JOIN schemas sc ON sc.schema_id = e.schema_id
  LEFT JOIN event_tags et ON et.event_id = e.event_id
  AND et.partition_month = date_trunc('month', fi.ts)::date
  LEFT JOIN tags t ON t.tag_id = et.tag_id
GROUP BY e.event_id,
  fi.ts,
  s.subject_key,
  p.name,
  sc.name,
  sc.version,
  e.payload
ORDER BY fi.ts DESC
LIMIT 1000;
-- 3) partition_sizes: rough sizes by child tables
CREATE OR REPLACE VIEW partition_sizes AS
SELECT nm.relname AS table_name,
  pg_total_relation_size(nm.oid) AS total_size,
  pg_relation_size(nm.oid) AS table_size,
  pg_total_relation_size(nm.oid) - pg_relation_size(nm.oid) AS index_toast_size
FROM pg_class nm
  JOIN pg_inherits ih ON ih.inhrelid = nm.oid
  JOIN pg_class parent ON parent.oid = ih.inhparent
WHERE parent.relname IN ('events', 'event_tags')
ORDER BY total_size DESC;
-- 4) tag_popularity_month: top tags in recent months (from incremental stats)
CREATE OR REPLACE VIEW tag_popularity_month AS
SELECT stm.partition_month AS month,
  t.key,
  t.value,
  stm.event_count AS cnt
FROM public.stats_tag_month stm
  JOIN public.tags t ON t.tag_id = stm.tag_id
WHERE stm.partition_month >= date_trunc('month', now() - interval '6 months')::date
ORDER BY month DESC,
  cnt DESC;
-- 5) event_volume_month: monthly total events (from incremental stats)
CREATE OR REPLACE VIEW event_volume_month AS
SELECT partition_month AS month,
  event_count
FROM public.stats_event_month
WHERE partition_month >= date_trunc('month', now() - interval '12 months')::date
ORDER BY month DESC;