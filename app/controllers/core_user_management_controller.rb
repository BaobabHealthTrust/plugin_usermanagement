class CoreUserManagementController < ApplicationController
  unloadable

  # before_filter :__check_user, :except => [:login, :logout, :authenticate, :verify]

  # before_filter :__check_location, :except => [:login, :authenticate, :logout, :verify, :location, :location_update]

  def login

    redirect_to "clinic/index/#{params[:user_id]}" if !params[:user_id].blank?

  end

  def authenticate

    user = CoreUser.authenticate(params[:login], params[:password]) # rescue nil

    if user.nil?
      flash[:error] = "Wrong username or password!"
      redirect_to request.referrer and return
    end

    file = "#{File.expand_path("#{Rails.root}/tmp", __FILE__)}/user.login.yml"

    CoreUserProperty.find_by_user_id_and_property(user.id, "Status").delete rescue nil

    u = CoreUserProperty.create(
        :user_id => user.id,
        :property => "Status",
        :property_value => "ACTIVE"
    )

    CoreUserProperty.find_by_user_id_and_property(user.id, "Token").delete rescue nil

    u = CoreUserProperty.create(
        :user_id => user.id,
        :property => "Token",
        :property_value => CoreUser.random_string(16)
    )

    session[:token] = u.property_value
    session[:user_id] = u.user_id

    redirect_to "/core_user_management/location?user_id=#{user.id}&src=#{params[:src]}&token=#{session[:token]}" and return

  end

  def new_user
    @roles = CoreRole.find(:all).collect { |r| Vocabulary.search(r.role) }
  end

  def create_user

    existing = CoreUser.find_by_username(params[:login]) rescue nil

    if !existing.nil?
      flash[:error] = "Username already taken!"
      redirect_to "/core_user_management/new_user?user_id=#{session[:user_id]}&first_name=#{params[:first_name]
      }&last_name=#{params[:last_name]}&gender=#{params[:gender]}#{
      (!params[:src].nil? ? "&src=#{params[:src]}" : "")}" and return
    end

    user = CoreUser.create(
        :username => params[:login],
        :password => params[:password],
        :creator => params[:user_id],
        :date_created => Date.today,
        :uuid => ActiveRecord::Base.connection.select_one("SELECT UUID() as uuid")['uuid']
    )

    CoreUserProperty.create(
        :user_id => user.id,
        :property => "First Name",
        :property_value => (params[:first_name] rescue nil)
    )

    CoreUserProperty.create(
        :user_id => user.id,
        :property => "Last Name",
        :property_value => (params[:last_name] rescue nil)
    )

    CoreUserProperty.create(
        :user_id => user.id,
        :property => "Gender",
        :property_value => (params[:gender] rescue nil)
    )

    CoreUserProperty.create(
        :user_id => user.id,
        :property => "Status",
        :property_value => "PENDING"
    )

    params[:roles].each do |role|

      CoreUserRole.create(
          :user_id => user.id,
          :role => role
      )

    end

    redirect_to "/core_user_management/user_list?user_id=#{(params[:id] || params[:user_id])}&location_id=#{
    params[:location_id]}#{(!params[:src].nil? ? "&src=#{params[:src]}" : "")}" and return
  end

  def select_user_task

  end

  def user_list

    @destination = "/core_user_management/select_user_task?user_id=#{params[:user_id]}&location_id=#{params[:location_id]}"

    @users = CoreUser.find(:all).collect { |user|
      [
          user.name,
          user.username,
          user.gender,
          user.user_roles.collect { |r|
            r.role
          },
          (user.status.property_value rescue ""),
          user.id
      ]
    }

    if @user.status_value.to_s.downcase != "pending" and @user.status_value.to_s.downcase != "blocked"

      @can_edit = true

    else

      @can_edit = false

    end

    redirect_to "/login" and return if @user.nil?

  end

  def edit_user_status

    if params[:target_id].nil?
      flash[:error] = "Missing User ID!"
      redirect_to request.referrer and return
    end

    @target = CoreUser.find(params[:target_id]) rescue nil

  end

  def update_user_status

    property = CoreUserProperty.find_by_property_and_user_id("Status", params[:target_id]) rescue nil

    if property.nil?
      CoreUserProperty.create(
          :user_id => params[:target_id],
          :property => "Status",
          :property_value => (params[:status] rescue nil)
      )
    else
      property.update_attributes(:property_value => params[:status])
    end

    flash[:notice] = "Status changed to #{params[:status].upcase}"
    redirect_to "/core_user_management/user_list?user_id=#{session[:user_id]}&location_id=#{
    params[:location_id]}#{(!params[:src].nil? ? "&src=#{params[:src]}" : "")}" and return
  end

  def edit_roles

    @target = CoreUser.find(params[:target_id]) rescue nil

    current_roles = @target.user_roles.collect { |r| Vocabulary.search(r.role) }

    @roles = CoreRole.find(:all).collect { |r| Vocabulary.search(r.role) } - current_roles

  end

  def add_user_roles

    @target = CoreUser.find(params[:target_id]) rescue nil

    params[:roles].each do |role|

      CoreUserRole.create(
          :user_id => @target.id,
          :role => role
      )
    end

    redirect_to "/core_user_management/user_list?user_id=#{session[:user_id]}&location_id=#{
    params[:location_id]}#{(!params[:src].nil? ? "&src=#{params[:src]}" : "")}" and return
  end

  def void_role

    @target = CoreUser.find(params[:target_id]) rescue nil

    CoreUserRole.find_by_user_id_and_role(@target.id, params[:role]).delete rescue nil

    redirect_to "/core_user_management/user_list?user_id=#{session[:user_id]}&location_id=#{params[:location_id]
    }#{(!params[:src].nil? ? "&src=#{params[:src]}" : "")}" and return
  end

  def edit_user

    @first_name = CoreUserProperty.find_by_property_and_user_id("First Name", params[:user_id]).property_value rescue nil

    @last_name = CoreUserProperty.find_by_property_and_user_id("Last Name", params[:user_id]).property_value rescue nil

    @gender = CoreUserProperty.find_by_property_and_user_id("Gender", params[:user_id]).property_value rescue nil

  end

  def update_user

    fn_property = CoreUserProperty.find_by_property_and_user_id("First Name", params[:user_id]) rescue nil

    if fn_property.nil?
      CoreUserProperty.create(
          :user_id => params[:user_id],
          :property => "First Name",
          :property_value => (params[:first_name] rescue nil)
      )
    else
      fn_property.update_attributes(:property_value => params[:first_name])
    end

    ln_property = CoreUserProperty.find_by_property_and_user_id("Last Name", params[:user_id]) rescue nil

    if ln_property.nil?
      CoreUserProperty.create(
          :user_id => params[:user_id],
          :property => "Last Name",
          :property_value => (params[:last_name] rescue nil)
      )
    else
      ln_property.update_attributes(:property_value => params[:last_name])
    end

    gn_property = CoreUserProperty.find_by_property_and_user_id("Gender", params[:user_id]) rescue nil

    if gn_property.nil?
      CoreUserProperty.create(
          :user_id => params[:user_id],
          :property => "Gender",
          :property_value => (params[:gender] rescue nil)
      )
    else
      gn_property.update_attributes(:property_value => params[:gender])
    end

    flash[:notice] = "Demographics updated!"

    redirect_to "/" and return

  end

  def edit_password

  end

  def update_password
    old = CoreUser.authenticate(@user.username, params[:old_password]) # rescue nil

    if old.blank?
      flash[:error] = "Invalid current password!"

      redirect_to request.referrer and return
    end

    user = CoreUser.find(params[:user_id]) #rescue nil

    if !user.nil?

      user.update_attributes(:password => params[:password])

      flash[:notice] = "Password updated!"
    end

    redirect_to "/" and return

  end

  def logout

    request_link = params[:ext] ? request.referrer.split("?").first : ""

    user = CoreUserProperty.find_by_user_id_and_property(params[:id], "Token") rescue nil

    reset_session

    if user
      user.delete

      flash[:notice] = "You've been logged out"
    end

    redirect_to "/core_user_management/login" and return

  end

  def verify

    demo = CoreUser.find(params[:user_id] || params[:id]).demographics rescue {}

    render :text => demo.to_json
  end

  def location

  end

  def location_update

    if params[:location].strip.match(/^\d+$/)

      @location = CoreLocation.find(params[:location]) rescue nil

    else

      @location = CoreLocation.find_by_name(params[:location]) rescue nil

    end

    if @location.nil?

      flash[:error] = "Invalid location"

      redirect_to "/core_user_management/location?user_id=#{session[:user_id]}&src=#{params[:src]}&token=#{session[:token]}" and return

    end

    session[:location_id] = @location.id

    session[:sso_location] = @location.id

    redirect_to "/" and return

  end

  def user_demographics
    render :layout => false
  end

  protected

  def __check_user

    token = session[:token] rescue nil

    if token.nil?
      redirect_to "/core_user_management/login" and return
    else
      @user = CoreUser.find(session[:user_id]) rescue nil

      if @user.nil?
        redirect_to "/core_user_management/login" and return
      end
    end

  end

  def __check_location

    location = session[:location_id] rescue nil

    if location.nil?
      redirect_to "/core_user_management/location?user_id=#{session[:user_id]}" and return if !session[:user_id].nil?
    end

  end

end
