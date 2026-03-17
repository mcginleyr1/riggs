defmodule Murtaugh.Detection.Threat do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "threats" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :event_id, :binary_id
    field :storyline_id, :binary_id
    field :threat_level, :string
    field :final_score, :float
    field :status, :string, default: "open"
    field :assigned_to_email, :string
    field :resolved_at, :utc_datetime
    field :resolution_note, :string
    field :timestamp, :utc_datetime
    field :received_at, :utc_datetime
    field :verdicts, :map
    field :process_name, :string
    field :process_path, :string
    field :summary, :string
  end

  def changeset(threat, attrs) do
    threat
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :event_id,
      :storyline_id,
      :threat_level,
      :final_score,
      :status,
      :assigned_to_email,
      :resolved_at,
      :resolution_note,
      :timestamp,
      :received_at,
      :verdicts,
      :process_name,
      :process_path,
      :summary
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :event_id,
      :storyline_id,
      :threat_level,
      :final_score,
      :timestamp,
      :verdicts
    ])
    |> validate_inclusion(:status, ~w(open investigating resolved false_positive))
    |> validate_inclusion(:threat_level, ~w(suspicious malicious))
    |> validate_number(:final_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
  end

  def status_changeset(threat, attrs) do
    threat
    |> cast(attrs, [:status, :assigned_to_email, :resolved_at, :resolution_note])
    |> validate_required([:status])
    |> validate_inclusion(:status, ~w(open investigating resolved false_positive))
  end
end
