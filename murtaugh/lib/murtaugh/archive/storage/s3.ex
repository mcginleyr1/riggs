defmodule Murtaugh.Archive.Storage.S3 do
  @moduledoc """
  S3-compatible object storage backend.

  Works with AWS S3, MinIO, DigitalOcean Spaces, Backblaze B2,
  and GCS via its S3-compatible XML API. Custom endpoints are
  configured via :murtaugh, Murtaugh.Archive, :s3_endpoint.
  """

  @behaviour Murtaugh.Archive.Storage

  @impl true
  def put(bucket, key, body, opts \\ []) do
    content_type = Keyword.get(opts, :content_type, "application/octet-stream")

    bucket
    |> ExAws.S3.put_object(key, body, content_type: content_type)
    |> request()
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def get(bucket, key) do
    bucket
    |> ExAws.S3.get_object(key)
    |> request()
    |> case do
      {:ok, %{body: body}} -> {:ok, body}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def list(bucket, prefix) do
    bucket
    |> ExAws.S3.list_objects(prefix: prefix)
    |> ExAws.stream!(ex_aws_config())
    |> Enum.map(& &1.key)
    |> then(&{:ok, &1})
  rescue
    e -> {:error, e}
  end

  @impl true
  def delete(bucket, key) do
    bucket
    |> ExAws.S3.delete_object(key)
    |> request()
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def presigned_url(bucket, key, expires_in) do
    config = ex_aws_config()

    ExAws.S3.presigned_url(config, :get, bucket, key, expires_in: expires_in)
  end

  defp request(op) do
    ExAws.request(op, ex_aws_config())
  end

  defp ex_aws_config do
    archive_config = Application.get_env(:murtaugh, Murtaugh.Archive, [])

    base = [
      region: Keyword.get(archive_config, :s3_region, "us-east-1"),
      access_key_id: Keyword.get(archive_config, :s3_access_key, ""),
      secret_access_key: Keyword.get(archive_config, :s3_secret_key, "")
    ]

    case Keyword.get(archive_config, :s3_endpoint) do
      nil ->
        base

      endpoint ->
        %URI{host: host, port: port, scheme: scheme} = URI.parse(endpoint)

        Keyword.merge(base,
          host: host,
          port: port,
          scheme: scheme <> "://",
          s3: [
            scheme: scheme <> "://",
            host: host,
            port: port
          ]
        )
    end
  end
end
