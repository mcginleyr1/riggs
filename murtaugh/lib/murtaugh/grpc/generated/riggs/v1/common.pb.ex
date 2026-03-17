defmodule Riggs.V1.ProcessContext do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :pid, 1, type: :uint32
  field :parent_pid, 2, type: :uint32
  field :name, 3, type: :string
  field :path, 4, type: :string
  field :cmd_line, 5, type: :string
  field :username, 6, type: :string
  field :file_hash, 7, type: :string
end

defmodule Riggs.V1.AgentCommand do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :command_id, 1, type: :string
  field :command_type, 2, type: :string
  field :payload_json, 3, type: :bytes
end
