defmodule Murtaugh.Archive.Storage.Local do
  @moduledoc """
  Local filesystem storage backend for development and air-gapped deployments.

  Files are stored under a configurable base path (defaults to
  /var/lib/murtaugh/archive). The bucket name becomes a subdirectory
  under the base path.
  """

  @behaviour Murtaugh.Archive.Storage

  @default_base_path "/var/lib/murtaugh/archive"

  @impl true
  def put(bucket, key, body, _opts \\ []) do
    path = full_path(bucket, key)

    path |> Path.dirname() |> File.mkdir_p!()
    File.write(path, body)
  end

  @impl true
  def get(bucket, key) do
    path = full_path(bucket, key)

    case File.read(path) do
      {:ok, _body} = ok -> ok
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def list(bucket, prefix) do
    dir = Path.join(base_path(), bucket)

    if File.dir?(dir) do
      keys =
        dir
        |> list_files_recursive()
        |> Enum.map(&Path.relative_to(&1, dir))
        |> Enum.filter(&String.starts_with?(&1, prefix))
        |> Enum.sort()

      {:ok, keys}
    else
      {:ok, []}
    end
  end

  @impl true
  def delete(bucket, key) do
    path = full_path(bucket, key)

    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def presigned_url(_bucket, _key, _expires_in) do
    {:error, :not_supported}
  end

  defp full_path(bucket, key) do
    Path.join([base_path(), bucket, key])
  end

  defp base_path do
    archive_config = Application.get_env(:murtaugh, Murtaugh.Archive, [])
    Keyword.get(archive_config, :local_path, @default_base_path)
  end

  defp list_files_recursive(dir) do
    dir
    |> File.ls!()
    |> Enum.flat_map(fn entry ->
      full = Path.join(dir, entry)

      if File.dir?(full) do
        list_files_recursive(full)
      else
        [full]
      end
    end)
  end
end
