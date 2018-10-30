from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

engine = create_engine('sqlite:///catalogitem.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

category1 = Category(name='Soccer')
session.add(category1)
session.commit()

item1 = Item(
        name='Football boot',
        description='''Football boots, called cleats or soccer shoes
        in North America, are an item of footwear worn when playing
        football. Those designed for grass pitches have studs on the
        outsole to aid grip.''',
        category=category1
        )
session.add(item1)
session.commit()

item2 = Item(
        name='Shin guard',
        description='''A shin guard or shin pad is a piece of equipment
            worn on the front of a player\'s shin to protect them
            from injury.''',
        category=category1
        )
session.add(item2)
session.commit()

item3 = Item(
        name='Uniforms',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        category=category1
        )
session.add(item3)
session.commit()

item4 = Item(
        name='Socks',
        description='''A sock is an item of clothing worn on the feet and often
        covering the ankle or some part of the calf. Some type of shoe or boot
        is typically worn over socks. In ancient times, socks were made from
        leather or matted animal hair. In the late 16th century, machine-knit
        socks were first produced.''',
        category=category1
        )
session.add(item4)
session.commit()

item5 = Item(
        name='Soccer Balls',
        description='''A football, soccer ball, or association football ball is
        the ball used in the sport of association football. The name of the
        ball varies according to whether the sport is called "football",
        "soccer", or "association football".''',
        category=category1)
session.add(item5)
session.commit()


category2 = Category(name='Basketball')
session.add(category2)
session.commit()

item6 = Item(
        name='Shoes',
        description='''A shoe is an item of footwear intended to protect and
        comfort the human foot while the wearer is doing various activities.
        Shoes are also used as an item of decoration and fashion. The design
        of shoes has varied enormously through time and from culture to
        culture, with appearance originally being tied to function.''',
        category=category2
        )
session.add(item6)
session.commit()

item7 = Item(
        name='Basketball Backboards',
        description='''A backboard is a piece of basketball equipment.
        It is a raised vertical board with an attached basket consisting of a
        net suspended from a hoop. It is made of a flat, rigid piece of, often
        Plexiglas or tempered glass which also has the properties of safety
        glass when accidentally shattered.''',
        category=category2
        )
session.add(item7)
session.commit()

item8 = Item(
        name='Uniforms',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        category=category2
        )
session.add(item8)
session.commit()

item9 = Item(
        name='Shot clock',
        description='''A shot clock is used in basketball to quicken the pace
        of the game. The shot clock is usually displayed above the backboard
        behind each goal. The shot clock times a play and provides that a team
        on offense that does not promptly try to score points loses possession
        of the ball.''',
        category=category2
        )
session.add(item9)
session.commit()

item10 = Item(
        name='Basketball',
        description='''A basketball is a spherical ball used in basketball games.
        Basketballs typically range in size from very small promotional items
        only a few inches in diameter to extra large balls nearly a foot in
        diameter used in training exercises. ... High school and junior leagues
        normally use NCAA, NBA or WNBA sized balls.''',
        category=category2)
session.add(item10)
session.commit()


category3 = Category(name='Baseball')
session.add(category3)
session.commit()

item11 = Item(
        name='Baseball glove',
        description='''A baseball glove or mitt is a large leather glove worn by
        baseball players of the defending team, which assists players in
        catching and fielding balls hit by a batter or thrown by a
        teammate.''',
        category=category3
        )
session.add(item11)
session.commit()

item12 = Item(
        name='Baseball Helmet',
        description='''A batting helmet is worn by batters in the game of
        baseball or softball. It is meant to protect the batter's head from
        errant pitches thrown by the pitcher. A batter who is "hit by pitch,"
        due to an inadvertent wild pitch or a pitcher's purposeful attempt to
        hit him, may be seriously, even fatally, injured.''',
        category=category3
        )
session.add(item12)
session.commit()

item13 = Item(
        name='Uniform',
        description='''A baseball uniform is a type of uniform worn by baseball
        players and, uniquely to baseball, coaches. Most baseball uniforms have
        the names and uniform numbers of players who wear them, usually on the
        backs of the uniforms to distinguish players from each other.''',
        category=category3
        )
session.add(item13)
session.commit()

item14 = Item(
        name='Baseball Bat',
        description='''A baseball bat is a smooth wooden or metal club used
        in the sport of baseball to hit the ball after it is thrown by the
        pitcher. By regulation it may be no more than 2.75 inches (70 mm) in
        diameter at the thickest part and no more than 42 inches (1,100 mm)
        long''',
        category=category3
        )
session.add(item14)
session.commit()

item15 = Item(
        name='Baseball',
        description='''Baseball is a bat-and-ball game played between two
        opposing teams who take turns batting and fielding. The game proceeds
        when a player on the fielding team, called the pitcher, throws a ball
        which a player on the batting team tries to hit with a bat.''',
        category=category3)
session.add(item15)
session.commit()


category4 = Category(name='Frisbee')
session.add(category4)
session.commit()

item16 = Item(
        name='Frisbee Disk',
        description='''In order to play ultimate frisbee you a need a frisbee
        (makes sense). The regulation size for a frisbee is 175 gram disc. ''',
        category=category4
        )
session.add(item16)
session.commit()

item17 = Item(
        name='Cones',
        description='''In order to properly play ultimte frisbee you need to
        label the endzones. the endzones are exactly. If you don't have cones,
        you can use shoes if you don't have cones with you. ''',
        category=category4
        )
session.add(item17)
session.commit()

item18 = Item(
        name='Uniforms',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        category=category4
        )
session.add(item18)
session.commit()

category5 = Category(name='Snowboarding')
session.add(category5)
session.commit()

category6 = Category(name='Rock Climbing')
session.add(category6)
session.commit()

category7 = Category(name='Fooseball')
session.add(category7)
session.commit()

category8 = Category(name='Skating')
session.add(category8)
session.commit()

category9 = Category(name='Hockey')
session.add(category9)
session.commit()

print 'categories has been added'
