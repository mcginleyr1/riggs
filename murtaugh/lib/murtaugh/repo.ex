defmodule Murtaugh.Repo do
  use Ecto.Repo,
    otp_app: :murtaugh,
    adapter: Ecto.Adapters.Postgres
end
