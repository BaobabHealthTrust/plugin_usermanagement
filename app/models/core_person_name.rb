class CorePersonName < ActiveRecord::Base
	self.establish_connection :usermanagement
  set_table_name "person_name"
  set_primary_key "person_name_id"
  include CoreOpenmrs

  belongs_to :person, :class_name => "CorePerson", :foreign_key => :person_id, :conditions => {:voided => 0}

  # Looks for the most commonly used element in the database and sorts the results based on the first part of the string
  def self.find_most_common(field_name, search_string)
    return self.find_by_sql([
    "SELECT DISTINCT #{field_name} AS #{field_name}, #{self.primary_key} AS id \
     FROM person_name \
     INNER JOIN person ON person.person_id = person_name.person_id \
     WHERE person.voided = 0 AND person_name.voided = 0 AND #{field_name} LIKE ? \
     GROUP BY #{field_name} ORDER BY INSTR(#{field_name},\"#{search_string}\") ASC, COUNT(#{field_name}) DESC, #{field_name} ASC LIMIT 10", "%#{search_string}%"])
  end
end
