defmodule MurtaughWeb.UIComponents do
  @moduledoc """
  Shared UI components for the Murtaugh security console.

  These are domain-specific building blocks used across LiveViews:
  threat badges, status indicators, stat cards, and time formatting.
  """
  use Phoenix.Component

  @doc """
  Renders a color-coded badge for threat levels.

  ## Examples

      <.threat_badge level={:malicious} />
      <.threat_badge level={:suspicious} />
  """
  attr :level, :atom, required: true

  def threat_badge(assigns) do
    {bg, text, label} =
      case assigns.level do
        :malicious -> {"bg-red-900/60 border-red-700", "text-red-300", "Malicious"}
        :suspicious -> {"bg-yellow-900/60 border-yellow-700", "text-yellow-300", "Suspicious"}
        :benign -> {"bg-green-900/60 border-green-700", "text-green-300", "Benign"}
        :unresolved -> {"bg-gray-700/60 border-gray-600", "text-gray-300", "Unresolved"}
        _ -> {"bg-gray-700/60 border-gray-600", "text-gray-300", to_string(assigns.level)}
      end

    assigns = assign(assigns, bg: bg, text: text, label: label)

    ~H"""
    <span class={"inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border #{@bg} #{@text}"}>
      {@label}
    </span>
    """
  end

  @doc """
  Renders a colored dot indicator for agent status.

  ## Examples

      <.status_dot status={:online} />
      <.status_dot status={:offline} />
  """
  attr :status, :atom, required: true

  def status_dot(assigns) do
    color =
      case assigns.status do
        :online -> "bg-green-400"
        :offline -> "bg-red-400"
        :degraded -> "bg-yellow-400"
        :contained -> "bg-orange-400"
        _ -> "bg-gray-400"
      end

    assigns = assign(assigns, color: color)

    ~H"""
    <span class="inline-flex items-center gap-1.5">
      <span class={"inline-block w-2 h-2 rounded-full #{@color}"} />
      <span class="text-sm text-gray-300 capitalize">{Atom.to_string(@status)}</span>
    </span>
    """
  end

  @doc """
  Renders a badge for event severity levels.

  ## Examples

      <.severity_badge severity={:critical} />
      <.severity_badge severity={:high} />
  """
  attr :severity, :atom, required: true

  def severity_badge(assigns) do
    {bg, text} =
      case assigns.severity do
        :critical -> {"bg-red-900/60 border-red-700", "text-red-300"}
        :high -> {"bg-orange-900/60 border-orange-700", "text-orange-300"}
        :medium -> {"bg-yellow-900/60 border-yellow-700", "text-yellow-300"}
        :low -> {"bg-blue-900/60 border-blue-700", "text-blue-300"}
        :info -> {"bg-gray-700/60 border-gray-600", "text-gray-300"}
        _ -> {"bg-gray-700/60 border-gray-600", "text-gray-300"}
      end

    assigns = assign(assigns, bg: bg, text: text)

    ~H"""
    <span class={"inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border #{@bg} #{@text}"}>
      {Atom.to_string(@severity) |> String.capitalize()}
    </span>
    """
  end

  @doc """
  Renders a relative time display from a DateTime.

  ## Examples

      <.time_ago at={~U[2026-03-17 10:00:00Z]} />
  """
  attr :at, :any, required: true

  def time_ago(assigns) do
    label =
      case assigns.at do
        nil ->
          "never"

        %DateTime{} = dt ->
          diff = DateTime.diff(DateTime.utc_now(), dt, :second)
          format_duration(diff)

        _other ->
          "unknown"
      end

    assigns = assign(assigns, label: label)

    ~H"""
    <span class="text-sm text-gray-400" title={to_string(@at)}>{@label}</span>
    """
  end

  defp format_duration(seconds) when seconds < 60, do: "#{seconds}s ago"
  defp format_duration(seconds) when seconds < 3600, do: "#{div(seconds, 60)}m ago"
  defp format_duration(seconds) when seconds < 86_400, do: "#{div(seconds, 3600)}h ago"
  defp format_duration(seconds), do: "#{div(seconds, 86_400)}d ago"

  @doc """
  Renders a dashboard stat card with label, value, and optional trend.

  ## Examples

      <.stat_card label="Online Agents" value="142" trend={:up} trend_value="+3" />
      <.stat_card label="Threats Today" value="7" />
  """
  attr :label, :string, required: true
  attr :value, :string, required: true
  attr :trend, :atom, default: nil, values: [:up, :down, nil]
  attr :trend_value, :string, default: nil
  attr :icon, :string, default: nil

  def stat_card(assigns) do
    ~H"""
    <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <div class="flex items-center justify-between">
        <p class="text-sm font-medium text-gray-400">{@label}</p>
        <span :if={@icon} class={"#{@icon} size-5 text-gray-500"} />
      </div>
      <div class="mt-2 flex items-baseline gap-2">
        <p class="text-3xl font-bold text-white">{@value}</p>
        <span
          :if={@trend && @trend_value}
          class={[
            "text-sm font-medium",
            @trend == :up && "text-green-400",
            @trend == :down && "text-red-400"
          ]}
        >
          {@trend_value}
        </span>
      </div>
    </div>
    """
  end
end
