class CoreGlobalProperty < ActiveRecord::Base
	self.establish_connection :usermanagement
  set_table_name "global_property"
  set_primary_key "property"
  include CoreOpenmrs

  def to_s
    return "#{property}: #{property_value}"
  end  

end
