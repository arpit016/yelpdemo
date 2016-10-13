class Restaurant < ActiveRecord::Base
  mount_uploader :image, ImageUploader
  
  searchkick
  
  has_many :reviews, dependent: :destroy
  
  validates :name, :address, :image, :phone, :website, presence: true
  validates :phone, format: { with: /\A\(\d{3}\) \d{3}-\d{4}\z/,
    message: "must be in the format (123) 456-7890" }
  
  validates :website, format: { with: /\Ahttps?:\/\/.*\z/,
    message: "must start with http:// or https://" }
end
