defmodule Murtaugh.Archive.PartitionManager do
  @moduledoc """
  Manages time-based table partitions in tenant databases.

  Handles creation of future monthly partitions, listing existing ones,
  identifying expired partitions, and dropping archived partitions.
  All operations use raw SQL since Ecto has no partition management support.
  """

  require Logger

  @doc """
  Creates future monthly partitions for `table` if they don't already exist.

  Generates partitions for the current month plus `months_ahead` additional
  months. Each partition covers a calendar month using range partitioning
  on a timestamp column.
  """
  @spec ensure_future_partitions(Ecto.Repo.t(), String.t(), non_neg_integer()) :: :ok
  def ensure_future_partitions(repo, table, months_ahead \\ 2) do
    today = Date.utc_today()
    existing = list_partition_names(repo, table)

    0..months_ahead
    |> Enum.each(fn offset ->
      date = Date.add(today, offset * 30)
      year = date.year
      month = date.month
      partition_name = partition_name(table, year, month)

      unless partition_name in existing do
        from_date = Date.new!(year, month, 1)
        to_date = next_month_start(year, month)

        sql = """
        CREATE TABLE IF NOT EXISTS #{partition_name}
        PARTITION OF #{table}
        FOR VALUES FROM ('#{Date.to_iso8601(from_date)}') TO ('#{Date.to_iso8601(to_date)}')
        """

        case Ecto.Adapters.SQL.query(repo, sql, []) do
          {:ok, _} ->
            Logger.info("Created partition #{partition_name}")

          {:error, %{postgres: %{code: :duplicate_table}}} ->
            :ok

          {:error, reason} ->
            Logger.error("Failed to create partition #{partition_name}: #{inspect(reason)}")
        end
      end
    end)
  end

  @doc """
  Lists all partitions for a given parent table.

  Returns a list of maps with :name, :year, :month, and :year_month keys.
  """
  @spec list_partitions(Ecto.Repo.t(), String.t()) :: [map()]
  def list_partitions(repo, table) do
    sql = """
    SELECT
      child.relname AS partition_name,
      pg_get_expr(child.relpartbound, child.oid) AS partition_bound
    FROM pg_inherits
    JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
    JOIN pg_class child ON pg_inherits.inhrelid = child.oid
    WHERE parent.relname = $1
    ORDER BY child.relname
    """

    case Ecto.Adapters.SQL.query(repo, sql, [table]) do
      {:ok, %{rows: rows}} ->
        Enum.map(rows, fn [name, _bound] ->
          {year, month} = parse_partition_date(name, table)
          %{name: name, year: year, month: month, year_month: format_year_month(year, month)}
        end)

      {:error, reason} ->
        Logger.error("Failed to list partitions for #{table}: #{inspect(reason)}")
        []
    end
  end

  @doc """
  Returns partitions that are older than `retention_days` from today.
  """
  @spec expired_partitions(Ecto.Repo.t(), String.t(), non_neg_integer()) :: [map()]
  def expired_partitions(repo, table, retention_days) do
    cutoff = Date.utc_today() |> Date.add(-retention_days)

    list_partitions(repo, table)
    |> Enum.filter(fn %{year: year, month: month} ->
      # A partition is expired if the last day of its month is before the cutoff
      last_day = Date.new!(year, month, 1) |> Date.end_of_month()
      Date.compare(last_day, cutoff) == :lt
    end)
  end

  @doc """
  Drops a partition table. Use only after the partition has been archived.
  """
  @spec drop_partition(Ecto.Repo.t(), String.t()) :: :ok | {:error, term()}
  def drop_partition(repo, partition_name) do
    sql = "DROP TABLE IF EXISTS #{partition_name}"

    case Ecto.Adapters.SQL.query(repo, sql, []) do
      {:ok, _} ->
        Logger.info("Dropped partition #{partition_name}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to drop partition #{partition_name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # -- Private --

  defp list_partition_names(repo, table) do
    list_partitions(repo, table) |> Enum.map(& &1.name)
  end

  defp partition_name(table, year, month) do
    "#{table}_#{year}_#{String.pad_leading(to_string(month), 2, "0")}"
  end

  defp format_year_month(year, month) do
    "#{year}-#{String.pad_leading(to_string(month), 2, "0")}"
  end

  defp next_month_start(year, 12), do: Date.new!(year + 1, 1, 1)
  defp next_month_start(year, month), do: Date.new!(year, month + 1, 1)

  defp parse_partition_date(partition_name, table) do
    prefix = table <> "_"

    suffix =
      partition_name
      |> String.replace_prefix(prefix, "")

    case String.split(suffix, "_") do
      [year_str, month_str | _] ->
        {String.to_integer(year_str), String.to_integer(month_str)}

      _ ->
        {0, 0}
    end
  end
end
