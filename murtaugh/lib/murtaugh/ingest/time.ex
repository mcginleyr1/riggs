defmodule Murtaugh.Ingest.Time do
  @moduledoc """
  Convert protobuf timestamps from agent reports into `DateTime`.

  Agents stamp each event with when it actually occurred on the endpoint. The
  ingesters must preserve that (for the forensic timeline and time-based
  aggregates) rather than substituting server receive-time.
  """

  @doc """
  Convert a `Google.Protobuf.Timestamp` to a second-precision `DateTime`,
  falling back to `fallback` when the timestamp is missing or unparseable.
  """
  def to_datetime(%Google.Protobuf.Timestamp{seconds: seconds}, fallback)
      when is_integer(seconds) and seconds > 0 do
    case DateTime.from_unix(seconds, :second) do
      {:ok, dt} -> dt
      _ -> fallback
    end
  end

  def to_datetime(_, fallback), do: fallback
end
