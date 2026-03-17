defmodule Murtaugh.Archive.Storage.Resolver do
  @moduledoc """
  Resolves the configured storage backend and delegates operations.

  Reads :storage from the archive config to pick the implementation module,
  and :bucket for the target bucket name. Provides convenience functions that
  call through to the active backend with the configured bucket.
  """

  alias Murtaugh.Archive.Storage

  @doc "Returns the storage module based on config."
  @spec impl() :: module()
  def impl do
    archive_config = Application.get_env(:murtaugh, Murtaugh.Archive, [])

    case Keyword.get(archive_config, :storage, "local") do
      "s3" -> Storage.S3
      "local" -> Storage.Local
      other -> raise "Unknown archive storage backend: #{inspect(other)}"
    end
  end

  @doc "Returns the configured bucket name."
  @spec bucket() :: String.t()
  def bucket do
    archive_config = Application.get_env(:murtaugh, Murtaugh.Archive, [])
    Keyword.get(archive_config, :bucket, "murtaugh-archive")
  end

  @doc "Upload an object to the configured bucket."
  @spec put(String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def put(key, body, opts \\ []) do
    impl().put(bucket(), key, body, opts)
  end

  @doc "Download an object from the configured bucket."
  @spec get(String.t()) :: {:ok, binary()} | {:error, term()}
  def get(key) do
    impl().get(bucket(), key)
  end

  @doc "List objects under a prefix in the configured bucket."
  @spec list(String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def list(prefix) do
    impl().list(bucket(), prefix)
  end

  @doc "Delete an object from the configured bucket."
  @spec delete(String.t()) :: :ok | {:error, term()}
  def delete(key) do
    impl().delete(bucket(), key)
  end

  @doc "Generate a presigned download URL."
  @spec presigned_url(String.t(), integer()) :: {:ok, String.t()} | {:error, term()}
  def presigned_url(key, expires_in \\ 3600) do
    impl().presigned_url(bucket(), key, expires_in)
  end
end
