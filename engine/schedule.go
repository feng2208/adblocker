package engine

import (
	"adblocker/config"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Schedule struct {
	Name string
	// Map weekday to list of allowed ranges for that day
	WeekMap map[time.Weekday][]TimeRange
}

type TimeRange struct {
	Start int // Minutes from midnight
	End   int // Minutes from midnight
}

type ScheduleMatcher struct {
	schedules map[string]*Schedule
}

func NewScheduleMatcher(cfg *config.Config) (*ScheduleMatcher, error) {
	sm := &ScheduleMatcher{
		schedules: make(map[string]*Schedule),
	}

	for _, s := range cfg.Schedules {
		sch := &Schedule{
			Name:    s.Name,
			WeekMap: make(map[time.Weekday][]TimeRange),
		}

		for _, item := range s.Items {
			// Parse Ranges for this item
			var currentRanges []TimeRange
			for _, rStr := range item.Ranges {
				tr, err := parseTimeRange(rStr)
				if err != nil {
					return nil, fmt.Errorf("invalid range '%s' in schedule '%s': %w", rStr, s.Name, err)
				}
				currentRanges = append(currentRanges, tr)
			}

			// Apply to days
			if len(item.Days) == 0 {
				// All days
				for d := time.Sunday; d <= time.Saturday; d++ {
					sch.WeekMap[d] = append(sch.WeekMap[d], currentRanges...)
				}
			} else {
				for _, dayStr := range item.Days {
					wd, err := parseWeekday(dayStr)
					if err != nil {
						return nil, fmt.Errorf("invalid day '%s' in schedule '%s'", dayStr, s.Name)
					}
					sch.WeekMap[wd] = append(sch.WeekMap[wd], currentRanges...)
				}
			}
		}

		sm.schedules[s.Name] = sch
	}

	return sm, nil
}

func (sm *ScheduleMatcher) IsActive(scheduleName string, t time.Time) bool {
	if scheduleName == "" {
		return false // No schedule = not in exclusion period = active
	}
	sch, ok := sm.schedules[scheduleName]
	if !ok {
		return false
	}

	// 1. Get ranges for current day
	ranges := sch.WeekMap[t.Weekday()]
	if len(ranges) == 0 {
		return false // No allowed ranges for this day -> Blocked (inactive)
	}

	// 2. Check Time
	currentMins := t.Hour()*60 + t.Minute()
	for _, r := range ranges {
		if currentMins >= r.Start && currentMins <= r.End {
			return true
		}
	}

	return false
}

func parseWeekday(s string) (time.Weekday, error) {
	switch strings.ToLower(s) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	}
	return 0, fmt.Errorf("unknown day")
}

func parseTimeRange(s string) (TimeRange, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return TimeRange{}, fmt.Errorf("format must be HH:MM-HH:MM")
	}
	start, err := parseMinutes(parts[0])
	if err != nil {
		return TimeRange{}, err
	}
	end, err := parseMinutes(parts[1])
	if err != nil {
		return TimeRange{}, err
	}
	return TimeRange{Start: start, End: end}, nil
}

func parseMinutes(hhmm string) (int, error) {
	parts := strings.Split(hhmm, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format")
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	return h*60 + m, nil
}
