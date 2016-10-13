class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
         
  has_many :reviews, dependent: :destroy #dependent destroy means if a user is deleted then all the reviews written by that user will also be deleted
  
  validates :first_name, :last_name, presence: true
end
