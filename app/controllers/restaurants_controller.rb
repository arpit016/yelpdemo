class RestaurantsController < ApplicationController
  before_action :set_restaurant, only: [:show, :edit, :update, :destroy]
  before_action :authenticate_user!, except: [:index, :show, :search]
  before_action :check_user, except: [:index, :show, :search]

  # GET /restaurants
  # GET /restaurants.json
  
  def search
    if params[:search].present?
      @restaurants = Restaurant.search(params[:search]) 
    else
      @restaurants = Restaurant.all
    end
  end
  
  
  def index
    @restaurants = Restaurant.paginate(page: params[:page], per_page: 2)
  end

  # GET /restaurants/1
  # GET /restaurants/1.json
  def show
    @reviews = Review.where(restaurant_id: @restaurant.id).order("created_at DESC").paginate(page: params[:page], per_page: 1)
    @reviews_length = Review.where(restaurant_id: @restaurant.id).order("created_at DESC")
    @review_writer = Review.where({restaurant_id: @restaurant.id, user_id: current_user.id})
    if @reviews_length.blank?
      @avg_rating = 0
    else
      @avg_rating = @reviews_length.average(:rating).round(2)
    end
  end

  # GET /restaurants/new
  def new
    @restaurant = Restaurant.new
  end

  # GET /restaurants/1/edit
  def edit
  end

  # POST /restaurants
  # POST /restaurants.json
  def create
    @restaurant = Restaurant.new(restaurant_params)

    respond_to do |format|
      if @restaurant.save
        format.html { redirect_to @restaurant, notice: 'Restaurant was successfully created.' }
        format.json { render :show, status: :created, location: @restaurant }
      else
        format.html { render :new }
        format.json { render json: @restaurant.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /restaurants/1
  # PATCH/PUT /restaurants/1.json
  def update
    respond_to do |format|
      if @restaurant.update(restaurant_params)
        format.html { redirect_to @restaurant, notice: 'Restaurant was successfully updated.' }
        format.json { render :show, status: :ok, location: @restaurant }
      else
        format.html { render :edit }
        format.json { render json: @restaurant.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /restaurants/1
  # DELETE /restaurants/1.json
  def destroy
    @restaurant.destroy
    respond_to do |format|
      format.html { redirect_to restaurants_url, notice: 'Restaurant was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_restaurant
      @restaurant = Restaurant.find(params[:id])
    end
    
    def check_user
      unless current_user.admin?
        redirect_to root_url, alert: "Sorry, only admins can do that"
      end
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def restaurant_params
      params.require(:restaurant).permit(:name, :address, :phone, :website, :image)
    end
end
