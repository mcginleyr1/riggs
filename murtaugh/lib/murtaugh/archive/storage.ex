defmodule Murtaugh.Archive.Storage do
  @moduledoc """
  Cloud-agnostic object storage interface.

  Backends implement this behaviour to support S3-compatible services,
  local filesystem, or any other object store. The active backend is
  selected at runtime via config :murtaugh, Murtaugh.Archive, storage: "s3" | "local".
  """

  @callback put(bucket :: String.t(), key :: String.t(), body :: binary(), opts :: keyword()) ::
              :ok | {:error, term()}

  @callback get(bucket :: String.t(), key :: String.t()) ::
              {:ok, binary()} | {:error, term()}

  @callback list(bucket :: String.t(), prefix :: String.t()) ::
              {:ok, [String.t()]} | {:error, term()}

  @callback delete(bucket :: String.t(), key :: String.t()) ::
              :ok | {:error, term()}

  @callback presigned_url(bucket :: String.t(), key :: String.t(), expires_in :: integer()) ::
              {:ok, String.t()} | {:error, term()}
end
