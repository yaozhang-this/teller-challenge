defmodule Teller do
  require HTTPoison
  require Poison
  require Base

  # The Internal Module handles the connection between Teller API and third-party banks
  defmodule Internal do
    # declare constant for each bank that can be reused
    # device id and user agent might change but for the sake of
    # this demo it is considered constant, can modify them in real production code
    @teller_bank_constants %{
      "url" => "https://test.teller.engineering",
      "api-key" => "HowManyGenServersDoesItTakeToCrackTheBank?",
      "user-agent" => "Teller Bank iOS 2.0",
      "device-id" => "KNBBFAKCGAYBRFKX",
      "app-json" => "application/json",
      "teller-mission" => "accepted!"
    }

    # To build a robust system that supports adding additional banks in the future
    # It is best to implemented functions that could be reused
    # So in this case, I implemented each function to handle just one process
    # and only that process of the integration

    # In the future, each of this internal function will handle differently according to each bank
    # Ideally we can see a pattern shared by most banks and delagate the
    # handling to helper functions for each bank

    # So that adding more banks does not require changing the function itself but
    # only the helper function that it calls
    # This way it is very easy to unit test each commit
    # and one problematic integration does not affect other integrations

    # But for this test I dont quite know if these headers are required by all banks
    # so I just did the case for the fake teller-bank
    def signin(username \\ "yellow_smokey", password \\ "gabon") do
      base_headers = [
        "user-agent": @teller_bank_constants["user-agent"],
        "api-key": @teller_bank_constants["api-key"],
        "device-id": @teller_bank_constants["device-id"],
        "content-type": @teller_bank_constants["app-json"],
        accept: @teller_bank_constants["app-json"]
      ]

      url = @teller_bank_constants["url"]

      body = get_signin_body(username, password)
      HTTPoison.start()

      # match response
      %HTTPoison.Response{status_code: status, body: body, headers: headers} =
        HTTPoison.post!("#{url}/signin", body, base_headers)

      # the data variable carries useful information for a particular function
      # they are not usually provided by the bank APIs themselves
      data = %{"username" => username}

      {status, body, headers, data}
    end

    def get_signin_body(username, password) do
      Poison.encode!(%{
        "password" => password,
        "username" => username
      })
    end

    def mfa({_status, body, headers, data}, method) do
      decoded_body = Poison.decode!(body)
      # mapped header for easier access
      mapped_headers = Enum.into(headers, %{})

      f_token =
        get_f_token(
          mapped_headers,
          data["username"],
          @teller_bank_constants["device-id"],
          @teller_bank_constants["api-key"]
        )

      r_token = mapped_headers["r-token"]
      devices = decoded_body["data"]["devices"]

      mfa_id =
        if method == "SMS" do
          List.first(devices)["id"]
        else
          List.last(devices)["id"]
        end

      base_headers = [
        "teller-mission": @teller_bank_constants["teller-mission"],
        "user-agent": @teller_bank_constants["user-agent"],
        "api-key": @teller_bank_constants["api-key"],
        "device-id": @teller_bank_constants["device-id"],
        "r-token": r_token,
        "f-token": f_token,
        "content-type": @teller_bank_constants["app-json"],
        accept: @teller_bank_constants["app-json"]
      ]

      url = @teller_bank_constants["url"]
      body = get_mfa_body(mfa_id)

      # send mfa request to server
      # if successful, make another request with the sms code

      %HTTPoison.Response{status_code: status, body: body, headers: headers} =
        HTTPoison.post!("#{url}/signin/mfa", body, base_headers)

      {status, body, headers, data}
    end

    def get_mfa_body(mfa_id) do
      Poison.encode!(%{
        "device_id" => mfa_id
      })
    end

    def get_f_token(mapped_headers, username, device_id, api_key) do
      # take f_token_spec and create valid f_token according to spec
      # we found the spec to be using sha-256-b64-np hash method

      # with (api-key|last-request-id|device-id) changing the delimeter and parameters
      # so we need to parse it

      f_token_spec = mapped_headers["f-token-spec"]

      spec = Base.decode64!(f_token_spec)

      # from spec, there seems be to a few variables appearing in pattern
      # - last-request-id
      # - username
      # - device-id
      # - api-key

      last_request_id = mapped_headers["f-request-id"]

      # it is sufficient to use index 14 for this test
      # but can use something better to dynamically separete the hash method from different patterns
      clear_spec = String.slice(spec, 15..(String.length(spec) - 2))

      interpoloated_payload =
        clear_spec
        |> String.replace("last-request-id", last_request_id)
        |> String.replace("username", username)
        |> String.replace("device-id", device_id)
        |> String.replace("api-key", api_key)

      # use Sha 256 base 64 with no padding hash
      payload = Base.encode64(:crypto.hash(:sha256, interpoloated_payload), padding: false)
      payload
    end

    def verify({_status, _body, headers, data}, code) do
      # mapped header for easier access
      mapped_headers = Enum.into(headers, %{})

      f_token =
        get_f_token(
          mapped_headers,
          data["username"],
          @teller_bank_constants["device-id"],
          @teller_bank_constants["api-key"]
        )

      r_token = mapped_headers["r-token"]

      base_headers = [
        "teller-mission": @teller_bank_constants["teller-mission"],
        "user-agent": @teller_bank_constants["user-agent"],
        "api-key": @teller_bank_constants["api-key"],
        "device-id": @teller_bank_constants["device-id"],
        "r-token": r_token,
        "f-token": f_token,
        "content-type": @teller_bank_constants["app-json"],
        accept: @teller_bank_constants["app-json"]
      ]

      url = @teller_bank_constants["url"]
      body = get_verify_body(code)

      %HTTPoison.Response{status_code: status, body: body, headers: headers} =
        HTTPoison.post!("#{url}/signin/mfa/verify", body, base_headers)

      {status, body, headers, data}
    end

    def get_verify_body(code) do
      Poison.encode!(%{
        "code" => "#{code}"
      })
    end

    def get_balances({_status, body, headers, data}, account_id, stored_enc_key) do
      decoded_body = Poison.decode!(body)
      # mapped header for easier access
      mapped_headers = Enum.into(headers, %{})

      f_token =
        get_f_token(
          mapped_headers,
          data["username"],
          @teller_bank_constants["device-id"],
          @teller_bank_constants["api-key"]
        )

      r_token = mapped_headers["r-token"]
      s_token = mapped_headers["s-token"]
      # checking_account = decoded_body["data"]["accounts"]["checking"]

      enc_key =
        if stored_enc_key == nil do
          decoded_body["data"]["enc_key"]
        else
          stored_enc_key
        end

      # a_token = decoded_body["data"]["a_token"]
      decoded_spec_raw = Base.decode64!(enc_key)
      decoded_spec = Poison.decode!(decoded_spec_raw)
      _cipher = decoded_spec["cipher"]
      _format = decoded_spec["format"]
      # format seems to be always AEAD-256-GCM(username)

      key = decoded_spec["key"]

      base_headers = [
        "teller-mission": @teller_bank_constants["teller-mission"],
        "user-agent": @teller_bank_constants["user-agent"],
        "api-key": @teller_bank_constants["api-key"],
        "device-id": @teller_bank_constants["device-id"],
        "r-token": r_token,
        "f-token": f_token,
        "s-token": s_token,
        "content-type": @teller_bank_constants["app-json"],
        accept: @teller_bank_constants["app-json"]
      ]

      url = @teller_bank_constants["url"]

      %HTTPoison.Response{status_code: status, body: body, headers: headers} =
        HTTPoison.get!("#{url}/accounts/#{account_id}/balances", base_headers)

      data = %{
        "username" => data["username"],
        "account_id" => account_id,
        "key" => key,
        "enc_key" => enc_key
      }

      {status, body, headers, data}
    end

    def get_details({_status, body, headers, data}) do
      username = data["username"]
      account_id = data["account_id"]
      key = data["key"]

      _decoded_body = Poison.decode!(body)
      # mapped header for easier access
      mapped_headers = Enum.into(headers, %{})

      f_token =
        get_f_token(
          mapped_headers,
          data["username"],
          @teller_bank_constants["device-id"],
          @teller_bank_constants["api-key"]
        )

      r_token = mapped_headers["r-token"]
      s_token = mapped_headers["s-token"]

      base_headers = [
        "teller-mission": @teller_bank_constants["teller-mission"],
        "user-agent": @teller_bank_constants["user-agent"],
        "api-key": @teller_bank_constants["api-key"],
        "device-id": @teller_bank_constants["device-id"],
        "r-token": r_token,
        "f-token": f_token,
        "s-token": s_token,
        "content-type": @teller_bank_constants["app-json"],
        accept: @teller_bank_constants["app-json"]
      ]

      url = @teller_bank_constants["url"]

      %HTTPoison.Response{status_code: status, body: body, headers: headers} =
        HTTPoison.get!("#{url}/accounts/#{account_id}/details", base_headers)

      decoded_body = Poison.decode!(body)
      number = decoded_body["number"]

      data = %{
        "username" => username,
        "account_id" => account_id,
        "key" => key,
        "number" => number
      }

      {status, body, headers, data}
    end

    def decrypt_account_number(data) do
      username = data["username"]
      key = data["key"]
      number = data["number"]

      decoded_key = Base.decode64!(key)
      # split the number string by : to get ct, iv, and t
      [encoded_ct, encoded_iv, encoded_t] = String.split(number, ":")
      # decode iv, to be 256 bits
      iv = Base.decode64!(encoded_iv)
      t = Base.decode64!(encoded_t)
      ct = Base.decode64!(encoded_ct)
      {ct, iv, t}
      mode = :aes_256_gcm
      # From documentation the decryption syntax for AEAD-256-GCM mode
      # crypto_one_time_aead(Cipher, Key, IV, InText, AAD, TagOrTagLength, EncFlag) -> Result
      account_number = :crypto.crypto_one_time_aead(mode, decoded_key, iv, ct, username, t, false)
      account_number
    end
  end

  defmodule APIServer do
    use GenServer
    # A simple GenServer to handle the data store
    def init([]) do
      {:ok, %{}}
    end

    # k is a token in this case
    def handle_call({:replace, k, v}, _from, state) do
      next_state = Map.replace(state, k, v)
      {:reply, v, next_state}
    end

    def handle_call({:put, k, v}, _from, state) do
      next_state = Map.put(state, k, v)
      {:reply, next_state, next_state}
    end

    def handle_call({:get, k}, _from, state) do
      {:reply, Map.get(state, k), state}
    end
  end

  defmodule Customer do
    # API for customers
    def get_token() do
      # generate a unique secret of 256 byes as a token for customers

      # First time using this so this might not be best way to do things
      # For example, the token given to customers should be time-sensitive
      # But still need to learn more about Elixir
      key = :crypto.strong_rand_bytes(256)
      base64_key = Base.encode64(key)
      {status, _} = GenServer.start_link(APIServer, [], name: :gs)

      if status == :ok do
        {:ok, base64_key}
      else
        {:error, "API Error"}
      end
    end

    def enroll(_bank, username, password, token) do
      # enroll a user
      v = Teller.Internal.signin(username, password)
      GenServer.call(:gs, {:put, token, v})

      {status, body, _headers, _data} = v

      if status != 200 do
        {:error, "Failed to enroll user"}
      else
        if Poison.decode!(body)["result"] == "mfa_required" do
          {:ok, "mfa_required", ["SMS", "VOICE"]}
        else
          {:ok}
        end
      end
    end

    def choose_mfa_method(method, token) do
      # retrieve state from genserver
      state = GenServer.call(:gs, {:get, token})

      if state == nil do
        {:error, "User is not enrolled"}
      else
        v = Teller.Internal.mfa(state, method)
        {status, _body, _headers, _data} = v

        if status != 200 do
          {:error, "Failed to choose mfa method"}
        else
          GenServer.call(:gs, {:replace, token, v})
          {:ok}
        end
      end
    end

    def verify_mfa_with_code(code, token) do
      # retrieve state from genserver
      state = GenServer.call(:gs, {:get, token})

      if state == nil do
        {:error, "User is not enrolled"}
      else
        v = Teller.Internal.verify(state, code)
        {status, body, _headers, _data} = v

        if status != 200 do
          {:error, "Failed to verify MFA"}
        else
          GenServer.call(:gs, {:replace, token, v})
          # return available accounts for that user to customers
          {:ok, Poison.decode!(body)["data"]["accounts"]}
        end
      end
    end

    # return account information and associated transactions
    def get_account(account_id, token) do
      # retrieve state from genserver
      state = GenServer.call(:gs, {:get, token})
      stored_enc_key = GenServer.call(:gs, {:get, "#{token}+enc_key"})

      if state == nil do
        {:error, "User is not enrolled"}
      else
        v = Teller.Internal.get_balances(state, account_id, stored_enc_key)
        {status_balances, body_balances, _headers_balances, data_balances} = v
        decoded_balances = Poison.decode!(body_balances)
        GenServer.call(:gs, {:put, "#{token}+enc_key", data_balances["enc_key"]})

        if status_balances != 200 do
          {:error, "Failed to load account information"}
        else
          s = Teller.Internal.get_details(v)
          {_status_details, body_details, _headers_details, data_details} = s
          decoded_details = Poison.decode!(body_details)
          number = Teller.Internal.decrypt_account_number(data_details)

          details = %{
            "ach" => decoded_details["ach"],
            "alias" => decoded_details["alias"],
            "id" => decoded_details["id"],
            "number" => number,
            "product" => decoded_details["product"]
          }

          GenServer.call(:gs, {:replace, token, s})
          # return balances and account number
          {:ok, decoded_balances, details}
        end
      end
    end
  end
end

# example driver code for customer usage

{:ok, token} = Teller.Customer.get_token()
Teller.Customer.enroll("teller", "yellow_smokey", "gabon", token)
Teller.Customer.choose_mfa_method("SMS", token)
Teller.Customer.verify_mfa_with_code(123_456, token)
Teller.Customer.get_account("acc_u2fed4l2ozezh6rxbmn52bogaey2xiac6pfzt3q", token)

# as long as the token is intact, cutomer can repeatedly request information about that user's account
# Teller.Customer.get_account("acc_u2fed4l2ozezh6rxbmn52bogaey2xiac6pfzt3q", token)
