# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKeyEtsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.{Info, Strategy}
  alias Example.{EtsApiKey, UserWithEtsApiKey}

  # ETS compares a stored value with a filter's value as given, where a SQL data layer
  # converts both through the column's type.
  test "signs in with an API key kept in a data layer that compares values as given" do
    user = Ash.create!(UserWithEtsApiKey, %{email: "ets@example.com"}, authorize?: false)

    api_key =
      Ash.create!(
        EtsApiKey,
        %{user_id: user.id, expires_at: DateTime.add(DateTime.utc_now(), 3600)},
        authorize?: false
      )

    strategy = Info.strategy!(UserWithEtsApiKey, :api_key)

    assert {:ok, signed_in} =
             Strategy.action(
               strategy,
               :sign_in,
               %{api_key: api_key.__metadata__.plaintext_api_key},
               []
             )

    assert signed_in.id == user.id
    assert signed_in.__metadata__.api_key.id == api_key.id
  end
end
