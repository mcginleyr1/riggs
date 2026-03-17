defmodule Murtaugh.Archive do
  @moduledoc """
  Context for managing archived partition manifests.

  Provides CRUD operations on archive manifest entries in the meta DB
  and convenience access to presigned download URLs.
  """

  import Ecto.Query

  alias Murtaugh.Repo
  alias Murtaugh.Archive.Manifest
  alias Murtaugh.Archive.Storage.Resolver, as: Storage

  @doc "Lists all archived manifests for a given shard, ordered by table and date."
  @spec list_manifests(String.t()) :: [Manifest.t()]
  def list_manifests(shard_id) do
    from(m in Manifest,
      where: m.tenant_shard_id == ^shard_id,
      order_by: [asc: m.table_name, desc: m.year_month]
    )
    |> Repo.all()
  end

  @doc "Gets a single manifest entry. Raises if not found."
  @spec get_manifest!(String.t()) :: Manifest.t()
  def get_manifest!(id) do
    Repo.get!(Manifest, id)
  end

  @doc """
  Returns a presigned download URL for the archived file.

  Falls back to `{:error, :not_supported}` for backends that
  don't support presigned URLs (e.g., local filesystem).
  """
  @spec download_url(Manifest.t(), integer()) :: {:ok, String.t()} | {:error, term()}
  def download_url(%Manifest{object_key: key}, expires_in \\ 3600) do
    Storage.presigned_url(key, expires_in)
  end

  @doc "Creates a manifest entry in the meta DB."
  @spec record_manifest(map()) :: {:ok, Manifest.t()} | {:error, Ecto.Changeset.t()}
  def record_manifest(attrs) do
    %Manifest{}
    |> Manifest.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:object_key, :file_size_bytes, :row_count, :checksum, :status, :updated_at]},
      conflict_target: [:tenant_shard_id, :table_name, :year_month]
    )
  end

  @doc "Lists manifests for a shard filtered by table name."
  @spec list_manifests(String.t(), String.t()) :: [Manifest.t()]
  def list_manifests(shard_id, table_name) do
    from(m in Manifest,
      where: m.tenant_shard_id == ^shard_id and m.table_name == ^table_name,
      order_by: [desc: m.year_month]
    )
    |> Repo.all()
  end
end
