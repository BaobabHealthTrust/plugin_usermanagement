class Word < ActiveRecord::Base
	self.establish_connection :usermanagement

  belongs_to :vocabulary, :class_name => 'Vocabulary', :foreign_key => :vocabulary_id
  
end
