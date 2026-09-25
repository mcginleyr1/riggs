defmodule Murtaugh.Archive.Exporter do
  @moduledoc """
  Exports rows from a tenant database table to CSV and uploads to object storage.

  Streams rows from a specific table and year-month partition, writes them
  to a temporary CSV file, uploads to the configured storage backend, and
  records a manifest entry in the meta DB.
  """

  require Logger

  alias Murtaugh.Archive.Storage.Resolver, as: Storage
  alias Murtaugh.Tenancy

  @doc """
  Exports rows from `table_name` for the given `year_month` to a CSV file
  in object storage.

  The `shard` must be a `%Murtaugh.Org.Shard{}` struct. The `table_name` is
  the base table name (e.g., "events"). The `year_month` is a string like
  "2026-01".

  Returns `{:ok, %{key: key, size: size, rows: rows}}` on success.
  """
  @spec export_table(Murtaugh.Org.Shard.t(), String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def export_table(shard, table_name, year_month) do
    partition_name = partition_name(table_name, year_month)

    tmp_path =
      Path.join(
        System.tmp_dir!(),
        "murtaugh_export_#{partition_name}_#{System.unique_integer([:positive])}.csv"
      )

    try do
      with {:ok, row_count} <- export_to_csv(shard, partition_name, tmp_path),
           body = File.read!(tmp_path),
           key = archive_key(shard, table_name, year_month),
           :ok <- Storage.put(key, body, content_type: "text/csv"),
           checksum = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower),
           file_size = byte_size(body),
           {:ok, _manifest} <-
             record_manifest(shard, table_name, year_month, key, file_size, row_count, checksum) do
        Logger.info("Archived #{partition_name}: #{row_count} rows, #{file_size} bytes -> #{key}")
        {:ok, %{key: key, size: file_size, rows: row_count}}
      end
    after
      File.rm(tmp_path)
    end
  end

  defp export_to_csv(shard, partition_name, tmp_path) do
    Tenancy.with_tenant(shard, fn ->
      case Ecto.Adapters.SQL.query(
             Murtaugh.TenantRepo,
             "SELECT * FROM #{partition_name} ORDER BY 1",
             []
           ) do
        {:ok, %{columns: columns, rows: rows, num_rows: num_rows}} ->
          file = File.open!(tmp_path, [:write, :utf8])

          try do
            IO.write(file, encode_csv_row(columns))

            Enum.each(rows, fn row ->
              IO.write(file, encode_csv_row(Enum.map(row, &to_csv_value/1)))
            end)
          after
            File.close(file)
          end

          {:ok, num_rows}

        {:error, reason} ->
          {:error, {:query_failed, reason}}
      end
    end)
  end

  defp encode_csv_row(fields) do
    Enum.map_join(fields, ",", &escape_csv_field/1) <> "\n"
  end

  defp escape_csv_field(nil), do: ""

  defp escape_csv_field(field) when is_binary(field) do
    if String.contains?(field, [",", "\"", "\n", "\r"]) do
      "\"" <> String.replace(field, "\"", "\"\"") <> "\""
    else
      field
    end
  end

  defp escape_csv_field(field), do: to_string(field)

  defp to_csv_value(nil), do: nil
  defp to_csv_value(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp to_csv_value(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp to_csv_value(%Date{} = d), do: Date.to_iso8601(d)
  defp to_csv_value(%Time{} = t), do: Time.to_iso8601(t)
  defp to_csv_value(%Decimal{} = d), do: Decimal.to_string(d)
  defp to_csv_value(val) when is_map(val), do: Jason.encode!(val)
  defp to_csv_value(val) when is_list(val), do: Jason.encode!(val)
  defp to_csv_value(val) when is_binary(val), do: val
  defp to_csv_value(val), do: to_string(val)

  defp archive_key(shard, table_name, year_month) do
    "#{shard.name}/#{table_name}/#{year_month}.csv"
  end

  defp partition_name(table_name, year_month) do
    suffix = String.replace(year_month, "-", "_")
    "#{table_name}_#{suffix}"
  end

  defp record_manifest(shard, table_name, year_month, key, file_size, row_count, checksum) do
    Murtaugh.Archive.record_manifest(%{
      tenant_shard_id: shard.id,
      table_name: table_name,
      year_month: year_month,
      object_key: key,
      file_size_bytes: file_size,
      row_count: row_count,
      checksum: "sha256:#{checksum}",
      status: "completed"
    })
  end
end
