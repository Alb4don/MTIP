Feature: Correlating mobile threat intelligence
  Analysts need duplicate-free indicators, a clear line between what sources say and what the platform infers,
  and a model that learns from their verdicts.

  Scenario: Duplicates reported by two sources are merged into one indicator
    Given a fresh platform
    And the source "feed-a" reports the family bundle
    When the source "feed-b" reports "NODE0.fam0-cloudops.com" without attribution
    Then the platform holds 1 indicator with that value
    And 1 duplicate observation was eliminated

  Scenario: Inferences never overwrite documented associations
    Given a fresh platform
    And the source "feed-a" reports the family bundle
    And the source "feed-b" reports "fresh.fam1-cloudops.com" without attribution
    When the analyst runs a correlation
    Then "fresh.fam1-cloudops.com" is inferred to belong to "FamFamily1"
    And no indicator documented by a source carries an inferred attribution

  Scenario: An analyst confirmation turns an inference into a documented association
    Given a fresh platform
    And the source "feed-a" reports the family bundle
    And the source "feed-b" reports "fresh.fam1-cloudops.com" without attribution
    And the analyst runs a correlation
    When the analyst confirms the inference for "fresh.fam1-cloudops.com"
    Then "fresh.fam1-cloudops.com" is documented by "analyst" as "FamFamily1"
    And the reliability of "feed-a" increased

  Scenario: Shared hosting never links unrelated tenants
    Given a fresh platform
    And the source "feed-a" reports the family bundle
    And the source "feed-b" reports "tenant.firebaseio.com" without attribution
    When the analyst runs a correlation
    Then "tenant.firebaseio.com" has no inferred attribution
